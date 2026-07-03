use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    Network,
    Crypto,
    Filesystem,
    Process,
}

impl Capability {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Crypto => "crypto",
            Self::Filesystem => "filesystem",
            Self::Process => "process",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "network" | "net" => Some(Self::Network),
            "crypto" | "crypt" => Some(Self::Crypto),
            "filesystem" | "fs" | "file" => Some(Self::Filesystem),
            "process" | "proc" | "exec" => Some(Self::Process),
            _ => None,
        }
    }

    #[must_use]
    pub fn classify(symbol: &str) -> Option<Self> {
        let n: String = symbol.trim_start_matches('_').to_ascii_lowercase();
        if NETWORK_APIS.iter().any(|k: &&str| n.contains(k)) {
            return Some(Self::Network);
        }
        if CRYPTO_APIS.iter().any(|k: &&str| n.contains(k)) {
            return Some(Self::Crypto);
        }
        if PROCESS_APIS.iter().any(|k: &&str| n.contains(k)) {
            return Some(Self::Process);
        }
        if FILESYSTEM_APIS.iter().any(|k: &&str| n.contains(k)) {
            return Some(Self::Filesystem);
        }
        None
    }
}

const NETWORK_APIS: &[&str] = &[
    "socket",
    "connect",
    "wsastartup",
    "wsaconnect",
    "send",
    "recv",
    "bind",
    "listen",
    "accept",
    "gethostbyname",
    "getaddrinfo",
    "inet_addr",
    "internetopen",
    "internetconnect",
    "httpopenrequest",
    "httpsendrequest",
    "urldownloadtofile",
    "winhttpopen",
    "curl_easy",
];

const CRYPTO_APIS: &[&str] = &[
    "cryptencrypt",
    "cryptdecrypt",
    "cryptacquirecontext",
    "cryptgenkey",
    "cryptderivekey",
    "crypthashdata",
    "bcryptencrypt",
    "bcryptdecrypt",
    "evp_encrypt",
    "evp_decrypt",
    "evp_cipher",
    "aes_encrypt",
    "aes_decrypt",
    "aes_set",
    "sha256",
    "sha1_",
    "md5_",
    "rc4",
    "chacha20",
    "rsa_",
];

const PROCESS_APIS: &[&str] = &[
    "createprocess",
    "shellexecute",
    "winexec",
    "system",
    "execve",
    "execv",
    "execl",
    "fork",
    "posix_spawn",
    "createremotethread",
    "ntcreatethread",
    "virtualallocex",
    "writeprocessmemory",
];

const FILESYSTEM_APIS: &[&str] = &[
    "createfile",
    "readfile",
    "writefile",
    "deletefile",
    "fopen",
    "fwrite",
    "fread",
    "remove",
    "unlink",
    "open64",
    "openat",
    "movefile",
    "copyfile",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    Functions,
    CallsTo { target: String },
    XrefsTo { symbol: String },
    StringDecoders,
    ComplexityOver { threshold: u32 },
    CapabilitySites { capability: Capability },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionMatch {
    pub name: String,
    pub address: u64,
    pub instruction_count: usize,
    pub complexity: u32,
    pub is_export: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CallSiteMatch {
    pub caller: String,
    pub call_offset: u64,
    pub target: String,
    pub target_address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct XrefMatch {
    pub from_function: Option<String>,
    pub from_offset: u64,
    pub mnemonic: String,
    pub to_symbol: String,
    pub to_address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecoderMatch {
    pub name: String,
    pub address: u64,
    pub loop_back_edges: u32,
    pub byte_arith_ops: u32,
    pub memory_ops: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilitySiteMatch {
    pub function: Option<String>,
    pub offset: u64,
    pub mnemonic: String,
    pub symbol: String,
    pub capability: Capability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "query", rename_all = "kebab-case")]
pub enum QueryResult {
    Functions {
        matches: Vec<FunctionMatch>,
    },
    CallsTo {
        target: String,
        matches: Vec<CallSiteMatch>,
    },
    XrefsTo {
        symbol: String,
        matches: Vec<XrefMatch>,
    },
    StringDecoders {
        matches: Vec<DecoderMatch>,
    },
    ComplexityOver {
        threshold: u32,
        matches: Vec<FunctionMatch>,
    },
    CapabilitySites {
        capability: Capability,
        matches: Vec<CapabilitySiteMatch>,
    },
}

impl QueryResult {
    #[must_use]
    pub const fn count(&self) -> usize {
        match self {
            Self::Functions { matches } | Self::ComplexityOver { matches, .. } => matches.len(),
            Self::CallsTo { matches, .. } => matches.len(),
            Self::XrefsTo { matches, .. } => matches.len(),
            Self::StringDecoders { matches } => matches.len(),
            Self::CapabilitySites { matches, .. } => matches.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_parses_aliases() {
        assert_eq!(Capability::parse("net"), Some(Capability::Network));
        assert_eq!(Capability::parse("CRYPTO"), Some(Capability::Crypto));
        assert_eq!(Capability::parse(" fs "), Some(Capability::Filesystem));
        assert_eq!(Capability::parse("exec"), Some(Capability::Process));
        assert_eq!(Capability::parse("nonsense"), None);
    }

    #[test]
    fn result_count_reflects_matches() {
        let r: QueryResult = QueryResult::Functions {
            matches: vec![FunctionMatch {
                name: "f".to_owned(),
                address: 0,
                instruction_count: 1,
                complexity: 1,
                is_export: false,
            }],
        };
        assert_eq!(r.count(), 1);
    }
}
