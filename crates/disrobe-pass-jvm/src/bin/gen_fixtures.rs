#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]

use std::fs::File;
use std::io::Write as _;
use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let corpus: PathBuf = corpus_dir();
    std::fs::create_dir_all(&corpus)?;
    let class_bytes: Vec<u8> = build_minimal_class();
    let class_path: PathBuf = corpus.join("Hello.class");
    File::create(&class_path)?.write_all(&class_bytes)?;
    let jar_bytes: Vec<u8> = build_two_class_jar(&class_bytes)?;
    let jar_path: PathBuf = corpus.join("two_class.jar");
    File::create(&jar_path)?.write_all(&jar_bytes)?;
    println!("wrote {}", class_path.display());
    println!("wrote {}", jar_path.display());
    Ok(())
}

fn corpus_dir() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("corpus");
    p
}

fn build_minimal_class() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(128);
    out.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&52u16.to_be_bytes());
    out.extend_from_slice(&7u16.to_be_bytes());
    out.push(7);
    out.extend_from_slice(&2u16.to_be_bytes());
    out.push(1);
    let n1: &[u8] = b"Hello";
    out.extend_from_slice(&(n1.len() as u16).to_be_bytes());
    out.extend_from_slice(n1);
    out.push(7);
    out.extend_from_slice(&4u16.to_be_bytes());
    out.push(1);
    let n2: &[u8] = b"java/lang/Object";
    out.extend_from_slice(&(n2.len() as u16).to_be_bytes());
    out.extend_from_slice(n2);
    out.push(1);
    let n3: &[u8] = b"greet";
    out.extend_from_slice(&(n3.len() as u16).to_be_bytes());
    out.extend_from_slice(n3);
    out.push(1);
    let n4: &[u8] = b"()V";
    out.extend_from_slice(&(n4.len() as u16).to_be_bytes());
    out.extend_from_slice(n4);
    out.extend_from_slice(&0x0021u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&3u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

fn build_two_class_jar(class_bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    let buffer: Vec<u8> = Vec::with_capacity(class_bytes.len() * 2 + 256);
    let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(buffer);
    let mut zip: zip::ZipWriter<std::io::Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
    let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o644);
    zip.start_file("META-INF/MANIFEST.MF", options)?;
    zip.write_all(b"Manifest-Version: 1.0\r\n\r\n")?;
    zip.start_file("Hello.class", options)?;
    zip.write_all(class_bytes)?;
    zip.start_file("World.class", options)?;
    zip.write_all(class_bytes)?;
    let cursor: std::io::Cursor<Vec<u8>> = zip.finish()?;
    Ok(cursor.into_inner())
}
