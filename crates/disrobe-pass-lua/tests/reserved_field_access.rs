#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_lua::decompile::decompile_chunk;
use disrobe_pass_lua::reader::read_auto;

fn fixture_bytes() -> Vec<u8> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("oracle_src");
    p.push("reserved_field.luac54");
    fs::read(&p).expect("reserved_field fixture must be tracked")
}

fn recovered_body() -> String {
    let chunk = read_auto(&fixture_bytes()).expect("parse reserved-field fixture");
    let out = decompile_chunk(&chunk).expect("decompile reserved-field fixture");
    out.source
}

#[test]
fn keyword_fields_use_bracket_form_not_bare_dot() {
    let src: String = recovered_body();
    assert!(
        src.contains("t[\"end\"]"),
        "reserved word 'end' must be indexed with a bracket string key, got:\n{src}"
    );
    assert!(
        src.contains("t[\"function\"]"),
        "reserved word 'function' must be indexed with a bracket string key, got:\n{src}"
    );
    assert!(
        !src.contains("t.end"),
        "t.end is a Lua syntax error and must never be emitted, got:\n{src}"
    );
    assert!(
        !src.contains("t.function"),
        "t.function is a Lua syntax error and must never be emitted, got:\n{src}"
    );
}

fn find_lua_interp() -> Option<String> {
    let mut candidates: Vec<String> = Vec::new();
    if let Ok(home) = std::env::var("LOCALAPPDATA") {
        candidates.push(format!("{home}/Programs/Lua/bin/lua.exe"));
    }
    candidates.extend(["lua5.4".to_owned(), "lua54".to_owned(), "lua".to_owned()]);
    for c in &candidates {
        let Ok(out) = Command::new(c).arg("-v").output() else {
            continue;
        };
        let mut banner: String = String::from_utf8_lossy(&out.stdout).into_owned();
        banner.push_str(&String::from_utf8_lossy(&out.stderr));
        if banner.contains("Lua 5.4") {
            return Some(c.clone());
        }
    }
    None
}

#[test]
fn recovered_body_reparses_under_real_lua() {
    let Some(interp): Option<String> = find_lua_interp() else {
        eprintln!("skip: no lua interpreter on box");
        return;
    };
    let src: String = recovered_body();
    let body: String = src
        .lines()
        .skip_while(|l: &&str| !l.trim_start().starts_with("function _main"))
        .skip(1)
        .take_while(|l: &&str| l.trim() != "end")
        .collect::<Vec<&str>>()
        .join("\n");
    let mut checker: PathBuf = std::env::temp_dir();
    checker.push(format!("disrobe_reserved_{}.lua", std::process::id()));
    let script: String = format!(
        "local chunk = [==[\n{body}\n]==]\nlocal ok, err = load(chunk)\nif not ok then\n  io.stderr:write(err)\n  os.exit(1)\nend\n"
    );
    {
        let mut f: fs::File = fs::File::create(&checker).expect("write checker script");
        f.write_all(script.as_bytes()).expect("write script bytes");
    }
    let status = Command::new(&interp)
        .arg(&checker)
        .output()
        .expect("run lua checker");
    let _ = fs::remove_file(&checker);
    assert!(
        status.status.success(),
        "recovered body must reparse under real lua; body was:\n{body}\nstderr:\n{}",
        String::from_utf8_lossy(&status.stderr)
    );
}
