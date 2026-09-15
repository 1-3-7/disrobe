use std::collections::BTreeMap;
use std::ops::Bound;

use disrobe_pass_native::{ImportStub, resolve_elf_plt_imports};
use goblin::Object;

const MAX_IMPORT_ENTRIES: usize = 1 << 17;
const MAX_STUB_SPAN: u64 = 0x10;

#[derive(Debug, Clone, Default)]
pub struct ImportMap {
    by_iat_va: BTreeMap<u64, String>,
    by_thunk_va: BTreeMap<u64, String>,
    names: Vec<String>,
}

impl ImportMap {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        match Object::parse(bytes) {
            Ok(Object::PE(pe)) => Self::from_pe(&pe),
            Ok(Object::Elf(_)) => Self::from_elf(bytes),
            _ => Self::default(),
        }
    }

    fn from_pe(pe: &goblin::pe::PE<'_>) -> Self {
        let mut by_iat_va: BTreeMap<u64, String> = BTreeMap::new();
        let mut names: Vec<String> = Vec::new();
        for imp in &pe.imports {
            if by_iat_va.len() >= MAX_IMPORT_ENTRIES {
                break;
            }
            let dll: &str = imp
                .dll
                .strip_suffix(".dll")
                .map_or(imp.dll, |value: &str| value);
            let resolved: String = resolve_import_name(dll, imp.name.as_ref(), imp.ordinal);
            let qualified: String = format!("{dll}!{resolved}");
            let Some(iat_offset): Option<u64> = u64::try_from(imp.offset).ok() else {
                continue;
            };
            let Some(iat_va): Option<u64> = pe.image_base.checked_add(iat_offset) else {
                continue;
            };
            by_iat_va.insert(iat_va, qualified.clone());
            names.push(qualified);
        }
        names.sort_unstable();
        names.dedup();
        Self {
            by_iat_va,
            by_thunk_va: BTreeMap::new(),
            names,
        }
    }

    fn from_elf(bytes: &[u8]) -> Self {
        let mut by_iat_va: BTreeMap<u64, String> = BTreeMap::new();
        let mut by_thunk_va: BTreeMap<u64, String> = BTreeMap::new();
        let mut names: Vec<String> = Vec::new();
        for stub in resolve_elf_plt_imports(bytes) {
            if by_thunk_va.len() >= MAX_IMPORT_ENTRIES {
                break;
            }
            let stub: ImportStub = stub;
            if stub.name.is_empty() {
                continue;
            }
            by_thunk_va.insert(stub.stub_address, stub.name.clone());
            by_iat_va.insert(stub.slot_address, stub.name.clone());
            names.push(stub.name);
        }
        names.sort_unstable();
        names.dedup();
        Self {
            by_iat_va,
            by_thunk_va,
            names,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_thunks(entries: &[(u64, String)]) -> Self {
        let by_thunk_va: BTreeMap<u64, String> = entries.iter().cloned().collect();
        let mut names: Vec<String> = by_thunk_va.values().cloned().collect();
        names.sort_unstable();
        names.dedup();
        Self {
            by_iat_va: BTreeMap::new(),
            by_thunk_va,
            names,
        }
    }

    #[must_use]
    pub fn name_at_iat(&self, iat_va: u64) -> Option<&str> {
        self.by_iat_va.get(&iat_va).map(String::as_str)
    }

    #[must_use]
    pub fn name_at_thunk(&self, thunk_va: u64) -> Option<&str> {
        let (start, name): (&u64, &String) = self.by_thunk_va.range(..=thunk_va).next_back()?;
        let next: u64 = self
            .by_thunk_va
            .range((Bound::Excluded(*start), Bound::Unbounded))
            .next()
            .map_or(u64::MAX, |(address, _): (&u64, &String)| *address);
        let end: u64 = start.saturating_add(MAX_STUB_SPAN).min(next);
        (thunk_va < end).then_some(name.as_str())
    }

    #[must_use]
    pub fn names(&self) -> &[String] {
        &self.names
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_iat_va.is_empty() && self.by_thunk_va.is_empty() && self.names.is_empty()
    }
}

fn resolve_import_name(dll: &str, name: &str, ordinal: u16) -> String {
    let by_ordinal: bool = name.is_empty() || name.starts_with("ORDINAL ");
    if by_ordinal
        && dll.eq_ignore_ascii_case("ws2_32")
        && let Some(canonical) = ws2_32_ordinal(ordinal)
    {
        return canonical.to_owned();
    }
    if name.is_empty() {
        format!("ordinal_{ordinal}")
    } else {
        name.to_owned()
    }
}

const fn ws2_32_ordinal(ordinal: u16) -> Option<&'static str> {
    Some(match ordinal {
        1 => "accept",
        2 => "bind",
        3 => "closesocket",
        4 => "connect",
        5 => "getpeername",
        6 => "getsockname",
        7 => "getsockopt",
        8 => "htonl",
        9 => "htons",
        10 => "ioctlsocket",
        11 => "inet_addr",
        12 => "inet_ntoa",
        13 => "listen",
        14 => "ntohl",
        15 => "ntohs",
        16 => "recv",
        17 => "recvfrom",
        18 => "select",
        19 => "send",
        20 => "sendto",
        21 => "setsockopt",
        22 => "shutdown",
        23 => "socket",
        52 => "gethostbyname",
        115 => "WSAStartup",
        116 => "WSACleanup",
        119 => "WSASocketA",
        120 => "WSASocketW",
        192 => "getaddrinfo",
        _ => return None,
    })
}

#[must_use]
pub fn parse_operand_memory_address(operand: &str) -> Option<u64> {
    let open: usize = operand.find('[')?;
    let close: usize = operand[open + 1..].find(']')? + open + 1;
    let inner: &str = operand[open + 1..close].trim();
    let body: &str = inner
        .strip_prefix("rel ")
        .map_or(inner, |value: &str| value);
    let token: &str = body
        .split(['+', '-', '*', ' '])
        .find(|t: &&str| is_hex_token(t))?;
    parse_hex_token(token)
}

fn is_hex_token(token: &str) -> bool {
    parse_hex_token(token).is_some()
}

fn parse_hex_token(token: &str) -> Option<u64> {
    let trimmed: &str = token.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }
    if let Some(hex) = trimmed
        .strip_suffix('h')
        .or_else(|| trimmed.strip_suffix('H'))
        && !hex.is_empty()
        && hex.chars().all(|c: char| c.is_ascii_hexdigit())
    {
        return u64::from_str_radix(hex, 16).ok();
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_iced_rel_memory_operand() {
        assert_eq!(
            parse_operand_memory_address("qword [rel 140010000h]"),
            Some(0x1_4001_0000)
        );
    }

    #[test]
    fn parses_plain_and_prefixed_forms() {
        assert_eq!(
            parse_operand_memory_address("qword [0x404000]"),
            Some(0x0040_4000)
        );
        assert_eq!(parse_operand_memory_address("[rip+0x2eff]"), Some(0x2eff));
    }

    #[test]
    fn rejects_register_only_memory() {
        assert_eq!(parse_operand_memory_address("[rax+rcx*4]"), None);
        assert_eq!(parse_operand_memory_address("rax"), None);
    }
}
