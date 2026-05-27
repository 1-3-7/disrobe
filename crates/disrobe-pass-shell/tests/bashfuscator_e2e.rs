#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use disrobe_pass_shell::{
    BashfuscatorLevel, BashfuscatorReport, Detection, Dialect, Family, detect, peel_indirection,
    reverse_bashfuscator,
};

#[test]
fn fixture_bashfuscator_base64_pipe_token_level() -> disrobe_pass_shell::Result<()> {
    let inner: &str = "uname -a; id";
    let b64: String = BASE64_STD.encode(inner);
    let src: String = format!("echo '{b64}' | base64 -d");
    let det: Detection = detect(src.as_bytes());
    assert_eq!(det.dialect, Dialect::Bash);
    assert!(matches!(
        det.family,
        Family::BashfuscatorCompress | Family::BashfuscatorToken | Family::Plain
    ));
    let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::Token, &src)?;
    assert!(r.output.contains(inner));
    Ok(())
}

#[test]
fn fixture_bash_ifs_indirection() -> disrobe_pass_shell::Result<()> {
    let src: &str = "#!/bin/bash\nc${IFS}a${IFS}t /etc/passwd";
    let det: Detection = detect(src.as_bytes());
    assert_eq!(det.dialect, Dialect::Bash);
    let r: disrobe_pass_shell::IndirectionReport = peel_indirection(src)?;
    assert!(r.output.contains("c a t /etc/passwd"));
    Ok(())
}

#[test]
fn fixture_bashfuscator_printf_string_level() -> disrobe_pass_shell::Result<()> {
    let src: &str = r"printf '\x69\x64'";
    let r: BashfuscatorReport = reverse_bashfuscator(BashfuscatorLevel::String, src)?;
    assert!(r.output.contains("id"));
    Ok(())
}
