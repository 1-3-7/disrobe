#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::doc_markdown
)]

use std::path::PathBuf;
use std::process::Command;

fn cli_binary() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir.file_name().and_then(|s| s.to_str()) != Some("debug")
        && dir.file_name().and_then(|s| s.to_str()) != Some("release")
    {
        if !dir.pop() {
            break;
        }
    }
    dir.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    dir
}

fn u30(mut value: u32, out: &mut Vec<u8>) {
    loop {
        let mut byte: u8 = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn build_abc() -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(&16u16.to_le_bytes());
    b.extend_from_slice(&46u16.to_le_bytes());

    u30(1, &mut b);
    u30(1, &mut b);
    u30(1, &mut b);
    let strings: [&str; 6] = ["", "Greeter", "Object", "trace", "greet", "hi"];
    u30(strings.len() as u32, &mut b);
    for s in &strings[1..] {
        u30(s.len() as u32, &mut b);
        b.extend_from_slice(s.as_bytes());
    }
    u30(2, &mut b);
    b.push(0x16);
    u30(0, &mut b);
    u30(1, &mut b);
    u30(5, &mut b);
    for name in [1u32, 2, 3, 4] {
        b.push(0x07);
        u30(1, &mut b);
        u30(name, &mut b);
    }

    u30(2, &mut b);
    emit_method_info(&mut b);
    emit_method_info(&mut b);

    u30(0, &mut b);

    u30(1, &mut b);
    u30(1, &mut b);
    u30(2, &mut b);
    b.push(0x00);
    u30(0, &mut b);
    u30(0, &mut b);
    u30(1, &mut b);
    u30(4, &mut b);
    b.push(0x01);
    u30(0, &mut b);
    u30(1, &mut b);

    u30(0, &mut b);
    u30(0, &mut b);

    u30(1, &mut b);
    u30(0, &mut b);
    u30(0, &mut b);

    let mut code: Vec<u8> = Vec::new();
    code.push(0xD0);
    code.push(0x30);
    code.push(0x5D);
    u30(3, &mut code);
    code.push(0x2C);
    u30(5, &mut code);
    code.push(0x4F);
    u30(3, &mut code);
    u30(1, &mut code);
    code.push(0x47);

    u30(1, &mut b);
    u30(1, &mut b);
    u30(2, &mut b);
    u30(1, &mut b);
    u30(1, &mut b);
    u30(2, &mut b);
    u30(code.len() as u32, &mut b);
    b.extend_from_slice(&code);
    u30(0, &mut b);
    u30(0, &mut b);
    b
}

fn emit_method_info(b: &mut Vec<u8>) {
    u30(0, b);
    u30(0, b);
    u30(0, b);
    b.push(0x00);
}

fn pack_tag(code: u16, payload: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    if payload.len() < 0x3F {
        let header: u16 = (code << 6) | (payload.len() as u16 & 0x3F);
        out.extend_from_slice(&header.to_le_bytes());
    } else {
        let header: u16 = (code << 6) | 0x3F;
        out.extend_from_slice(&header.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    }
    out.extend_from_slice(payload);
    out
}

fn build_swf() -> Vec<u8> {
    let abc: Vec<u8> = build_abc();
    let mut do_abc_payload: Vec<u8> = Vec::new();
    do_abc_payload.extend_from_slice(&0u32.to_le_bytes());
    do_abc_payload.extend_from_slice(b"Script");
    do_abc_payload.push(0);
    do_abc_payload.extend_from_slice(&abc);

    let mut body: Vec<u8> = Vec::new();
    body.push(0x00);
    body.extend_from_slice(&24u16.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&pack_tag(82, &do_abc_payload));
    body.extend_from_slice(&pack_tag(0, &[]));

    let mut swf: Vec<u8> = Vec::new();
    swf.extend_from_slice(b"FWS");
    swf.push(10);
    let file_length: u32 = (8 + body.len()) as u32;
    swf.extend_from_slice(&file_length.to_le_bytes());
    swf.extend_from_slice(&body);
    swf
}

#[test]
fn as3_disasm_source_emit_writes_lifted_bodies() {
    let bin: PathBuf = cli_binary();
    assert!(
        bin.exists(),
        "disrobe binary not built at {}; run `cargo build -p disrobe-cli` first",
        bin.display()
    );
    let swf_scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-as3-src")
            .expect("create scratch directory");
    let swf_path: PathBuf = swf_scratch.path().join("payload.swf");
    let out_scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-as3-out")
            .expect("create scratch directory");
    let out_dir: PathBuf = out_scratch.path().to_path_buf();
    std::fs::write(&swf_path, build_swf()).expect("write swf fixture");

    let output: std::process::Output = Command::new(&bin)
        .args([
            "as3",
            "disasm",
            swf_path.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
            "--emit",
            "source",
        ])
        .env_remove("RUST_LOG")
        .output()
        .expect("spawn disrobe");
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(
        output.status.code(),
        Some(0),
        "as3 disasm must succeed; stdout={stdout} stderr={stderr}"
    );

    let mut source: Option<String> = None;
    for entry in std::fs::read_dir(&out_dir).expect("read out dir") {
        let path: PathBuf = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) == Some("as3") {
            source = Some(std::fs::read_to_string(&path).expect("read as3"));
            break;
        }
    }
    let source: String = source.expect("a .source.as3 file must be emitted");
    assert!(
        source.contains("class Greeter"),
        "decompiled source must declare the class:\n{source}"
    );
    assert!(
        source.contains("public function greet"),
        "method signature must be recovered:\n{source}"
    );
    assert!(
        source.contains("trace(\"hi\")"),
        "method body must be lifted, not stubbed:\n{source}"
    );
    assert!(
        !source.contains("/* method */"),
        "no stub markers may remain:\n{source}"
    );
}
