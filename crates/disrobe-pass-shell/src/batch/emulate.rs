use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct EmuState {
    pub codepage: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmuResult {
    Output(String),
    Unresolved,
}

#[must_use]
pub fn emulate(command: &str, env: &BTreeMap<String, String>, state: &EmuState) -> EmuResult {
    let trimmed: &str = command.trim();
    let (head, rest): (&str, &str) = split_head(trimmed);
    match head.to_ascii_lowercase().as_str() {
        "set" => emulate_set(rest, env),
        "chcp" => emulate_chcp(rest, state),
        "echo" => emulate_echo(rest),
        _ => EmuResult::Unresolved,
    }
}

fn split_head(s: &str) -> (&str, &str) {
    match s.find(char::is_whitespace) {
        Some(at) => (&s[..at], s[at..].trim_start()),
        None => (s, ""),
    }
}

fn emulate_set(rest: &str, env: &BTreeMap<String, String>) -> EmuResult {
    let query: &str = rest.trim();
    if query.is_empty() || query.starts_with('/') {
        return EmuResult::Unresolved;
    }
    if query.contains('=') {
        return EmuResult::Unresolved;
    }
    let prefix: String = query.to_ascii_uppercase();
    let mut lines: Vec<String> = env
        .iter()
        .filter(|(k, _): &(&String, &String)| k.starts_with(&prefix))
        .map(|(k, v): (&String, &String)| format!("{k}={v}"))
        .collect();
    if lines.is_empty() {
        return EmuResult::Unresolved;
    }
    lines.sort();
    EmuResult::Output(lines.join("\n"))
}

fn emulate_chcp(rest: &str, state: &EmuState) -> EmuResult {
    let arg: &str = rest.trim();
    if arg.is_empty() {
        match state.codepage {
            Some(cp) => EmuResult::Output(format!("Active code page: {cp}")),
            None => EmuResult::Unresolved,
        }
    } else {
        match arg.parse::<u32>() {
            Ok(cp) => EmuResult::Output(format!("Active code page: {cp}")),
            Err(_) => EmuResult::Unresolved,
        }
    }
}

fn emulate_echo(rest: &str) -> EmuResult {
    let arg: &str = rest.trim();
    if arg.eq_ignore_ascii_case("off") || arg.eq_ignore_ascii_case("on") || arg.is_empty() {
        return EmuResult::Unresolved;
    }
    EmuResult::Output(arg.to_owned())
}

#[must_use]
pub fn scan_chcp(line: &str) -> Option<u32> {
    let trimmed: &str = line.trim();
    let (head, rest): (&str, &str) = split_head(trimmed);
    if head.eq_ignore_ascii_case("chcp") {
        rest.trim().parse::<u32>().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v): &(&str, &str)| (k.to_ascii_uppercase(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn set_query_resolves_known_var() {
        let env: BTreeMap<String, String> = env_of(&[("PATHEXT", ".COM;.EXE")]);
        let r: EmuResult = emulate("set PATHEXT", &env, &EmuState::default());
        assert_eq!(r, EmuResult::Output("PATHEXT=.COM;.EXE".to_owned()));
    }

    #[test]
    fn set_query_unknown_var_unresolved() {
        let r: EmuResult = emulate("set NOPE", &env_of(&[]), &EmuState::default());
        assert_eq!(r, EmuResult::Unresolved);
    }

    #[test]
    fn chcp_with_arg_is_deterministic() {
        let r: EmuResult = emulate("chcp 65001", &env_of(&[]), &EmuState::default());
        assert_eq!(r, EmuResult::Output("Active code page: 65001".to_owned()));
    }

    #[test]
    fn chcp_no_arg_uses_state() {
        let state: EmuState = EmuState {
            codepage: Some(437),
        };
        let r: EmuResult = emulate("chcp", &env_of(&[]), &state);
        assert_eq!(r, EmuResult::Output("Active code page: 437".to_owned()));
    }

    #[test]
    fn whoami_is_unresolved_never_fabricated() {
        let r: EmuResult = emulate("whoami", &env_of(&[]), &EmuState::default());
        assert_eq!(r, EmuResult::Unresolved);
    }

    #[test]
    fn dir_is_unresolved() {
        let r: EmuResult = emulate("dir C:\\", &env_of(&[]), &EmuState::default());
        assert_eq!(r, EmuResult::Unresolved);
    }

    #[test]
    fn echo_text_returns_text() {
        let r: EmuResult = emulate("echo hello", &env_of(&[]), &EmuState::default());
        assert_eq!(r, EmuResult::Output("hello".to_owned()));
    }
}
