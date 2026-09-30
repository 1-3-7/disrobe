use std::process::{Command, Output};

pub const ANY_LUA: &str = "disrobe-pass-lua::lua";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Lua51,
    Lua54,
    Lua55,
    LuaJit,
}

impl Dialect {
    pub const fn prerequisite(self) -> &'static str {
        match self {
            Self::Lua51 => "disrobe-pass-lua::lua-5.1",
            Self::Lua54 => "disrobe-pass-lua::lua-5.4",
            Self::Lua55 => "disrobe-pass-lua::lua-5.5",
            Self::LuaJit => "disrobe-pass-lua::luajit",
        }
    }

    const fn banner(self) -> &'static str {
        match self {
            Self::Lua51 => "Lua 5.1",
            Self::Lua54 => "Lua 5.4",
            Self::Lua55 => "Lua 5.5",
            Self::LuaJit => "LuaJIT 2.",
        }
    }

    const fn interpreters(self) -> &'static [&'static str] {
        match self {
            Self::Lua51 => &["lua5.1", "lua5.1.exe", "lua51", "lua"],
            Self::Lua54 => &["lua5.4", "lua5.4.exe", "lua54", "lua"],
            Self::Lua55 => &["lua5.5", "lua5.5.exe", "lua55", "lua"],
            Self::LuaJit => &["luajit"],
        }
    }

    const fn compilers(self) -> &'static [&'static str] {
        match self {
            Self::Lua51 => &["luac5.1", "luac5.1.exe", "luac51", "luac"],
            Self::Lua54 => &["luac5.4", "luac5.4.exe", "luac54", "luac"],
            Self::Lua55 => &["luac5.5", "luac5.5.exe", "luac55", "luac"],
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

pub fn missing_tool(prerequisite: &str, what: &str) {
    if let Err(error) = disrobe_testkit::require::<()>(prerequisite, what, None) {
        panic!("{error}");
    }
}

fn ungraded(dialect: Dialect, what: &str) {
    missing_tool(dialect.prerequisite(), &format!("{what} on PATH"));
}

pub fn interpreter(dialect: Dialect) -> Option<String> {
    let found: Option<String> = first_reporting(dialect.interpreters(), dialect.banner());
    if found.is_none() {
        ungraded(dialect, &format!("a `{}` interpreter", dialect.banner()));
    }
    found
}

pub fn compiler(dialect: Dialect) -> Option<String> {
    let found: Option<String> = first_reporting(dialect.compilers(), dialect.banner());
    if found.is_none() {
        ungraded(dialect, &format!("a `{}` luac", dialect.banner()));
    }
    found
}

pub fn toolchain(dialect: Dialect) -> Option<(String, String)> {
    let luac: Option<String> = first_reporting(dialect.compilers(), dialect.banner());
    let lua: Option<String> = first_reporting(dialect.interpreters(), dialect.banner());
    if let (Some(luac), Some(lua)) = (luac, lua) {
        return Some((luac, lua));
    }
    ungraded(
        dialect,
        &format!("a `{}` luac and interpreter", dialect.banner()),
    );
    None
}
