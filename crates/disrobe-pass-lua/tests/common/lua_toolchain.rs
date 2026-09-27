use std::process::{Command, Output};

pub const REQUIRE_LUA_TOOLCHAIN_VAR: &str = "DISROBE_REQUIRE_LUA_TOOLCHAIN";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Lua51,
    Lua54,
    LuaJit,
}

impl Dialect {
    const fn banner(self) -> &'static str {
        match self {
            Self::Lua51 => "Lua 5.1",
            Self::Lua54 => "Lua 5.4",
            Self::LuaJit => "LuaJIT 2.",
        }
    }

    const fn interpreters(self) -> &'static [&'static str] {
        match self {
            Self::Lua51 => &["lua5.1", "lua51", "lua"],
            Self::Lua54 => &["lua5.4", "lua54", "lua"],
            Self::LuaJit => &["luajit"],
        }
    }

    const fn compilers(self) -> &'static [&'static str] {
        match self {
            Self::Lua51 => &["luac5.1", "luac51", "luac"],
            Self::Lua54 => &["luac5.4", "luac54", "luac"],
            Self::LuaJit => &[],
        }
    }
}

fn reports(program: &str, banner: &str) -> bool {
    Command::new(program)
        .arg("-v")
        .output()
        .is_ok_and(|out: Output| {
            let text: String = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            text.contains(banner)
        })
}

fn first_reporting(candidates: &[&str], banner: &str) -> Option<String> {
    candidates
        .iter()
        .find(|program: &&&str| reports(program, banner))
        .map(|program: &&str| (*program).to_owned())
}

pub fn missing_tool(what: &str) {
    assert!(
        std::env::var_os(REQUIRE_LUA_TOOLCHAIN_VAR).is_none(),
        "{REQUIRE_LUA_TOOLCHAIN_VAR} is set, so this oracle must run: {what}"
    );
    eprintln!(
        "UNGRADED: {what}, so this oracle is not measured; set {REQUIRE_LUA_TOOLCHAIN_VAR}=1 \
         to fail instead"
    );
}

fn ungraded(what: &str) {
    missing_tool(&format!("{what} is not on PATH"));
}

pub fn interpreter(dialect: Dialect) -> Option<String> {
    let found: Option<String> = first_reporting(dialect.interpreters(), dialect.banner());
    if found.is_none() {
        ungraded(&format!("a `{}` interpreter", dialect.banner()));
    }
    found
}

pub fn compiler(dialect: Dialect) -> Option<String> {
    let found: Option<String> = first_reporting(dialect.compilers(), dialect.banner());
    if found.is_none() {
        ungraded(&format!("a `{}` luac", dialect.banner()));
    }
    found
}

pub fn toolchain(dialect: Dialect) -> Option<(String, String)> {
    let luac: Option<String> = first_reporting(dialect.compilers(), dialect.banner());
    let lua: Option<String> = first_reporting(dialect.interpreters(), dialect.banner());
    match (luac, lua) {
        (Some(luac), Some(lua)) => Some((luac, lua)),
        _ => {
            ungraded(&format!("a `{}` luac and interpreter", dialect.banner()));
            None
        }
    }
}
