use super::bytenode::NodeVersion;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RootNameTable {
    roots: &'static [(u32, &'static str)],
    read_only_heap: &'static [(u32, &'static str)],
}

impl RootNameTable {
    pub(crate) const fn for_node(node: NodeVersion) -> Option<Self> {
        match node {
            NodeVersion::Node18 => Some(Self {
                roots: V8_10_2_ROOTS,
                read_only_heap: V8_10_2_READ_ONLY_HEAP,
            }),
            NodeVersion::Node20 => Some(Self {
                roots: V8_11_3_ROOTS,
                read_only_heap: V8_11_3_READ_ONLY_HEAP,
            }),
            NodeVersion::Node22 => Some(Self {
                roots: V8_12_4_ROOTS,
                read_only_heap: V8_12_4_READ_ONLY_HEAP,
            }),
            NodeVersion::Node24 => Some(Self {
                roots: V8_13_6_ROOTS,
                read_only_heap: V8_13_6_READ_ONLY_HEAP,
            }),
            NodeVersion::Unknown => None,
        }
    }

    pub(crate) fn root_name(self, index: u32) -> Option<&'static str> {
        self.roots
            .binary_search_by_key(&index, |&(idx, _): &(u32, &'static str)| idx)
            .ok()
            .map(|pos: usize| self.roots[pos].1)
    }

    pub(crate) fn read_only_heap_name(self, chunk: u32, offset: u32) -> Option<&'static str> {
        if chunk != 0u32 {
            return None;
        }
        self.read_only_heap
            .binary_search_by_key(&offset, |&(off, _): &(u32, &'static str)| off)
            .ok()
            .map(|pos: usize| self.read_only_heap[pos].1)
    }
}

const V8_10_2_ROOTS: &[(u32, &str)] = &[(424u32, "length")];

const V8_10_2_READ_ONLY_HEAP: &[(u32, &str)] = &[];

const V8_11_3_ROOTS: &[(u32, &str)] = &[(155u32, "length")];

const V8_11_3_READ_ONLY_HEAP: &[(u32, &str)] = &[];

const V8_12_4_ROOTS: &[(u32, &str)] = &[(164u32, "length")];

const V8_12_4_READ_ONLY_HEAP: &[(u32, &str)] = &[];

const V8_13_6_ROOTS: &[(u32, &str)] = &[
    (171u32, "prototype"),
    (172u32, "name"),
    (175u32, "value"),
    (307u32, "type"),
    (352u32, "!"),
    (575u32, "add"),
    (580u32, "apply"),
    (598u32, "bind"),
    (611u32, "cause"),
    (613u32, "code"),
    (617u32, "console"),
    (633u32, "default"),
    (639u32, "done"),
    (666u32, "exec"),
    (670u32, "flags"),
    (682u32, "get"),
    (687u32, "global"),
    (691u32, "has"),
    (697u32, "id"),
    (701u32, "index"),
    (705u32, "input"),
    (724u32, "keys"),
    (738u32, "message"),
    (800u32, "reject"),
    (818u32, "set"),
    (826u32, "size"),
    (828u32, "source"),
    (830u32, "stack"),
    (856u32, "toString"),
    (1006u32, "constructor"),
    (1007u32, "length"),
    (1008u32, "next"),
    (1009u32, "resolve"),
    (1010u32, "then"),
    (1011u32, "valueOf"),
];

const V8_13_6_READ_ONLY_HEAP: &[(u32, &str)] = &[
    (42800u32, "join"),
    (46240u32, "all"),
    (54040u32, "entries"),
    (54096u32, "values"),
    (54208u32, "hasOwnProperty"),
    (54440u32, "call"),
    (54648u32, "concat"),
    (54896u32, "push"),
    (54992u32, "slice"),
    (55040u32, "splice"),
    (55064u32, "includes"),
    (55088u32, "indexOf"),
    (55112u32, "forEach"),
    (55136u32, "filter"),
    (55208u32, "map"),
    (55280u32, "reduce"),
    (56024u32, "charAt"),
    (56048u32, "charCodeAt"),
    (56328u32, "match"),
    (56480u32, "replace"),
    (56560u32, "split"),
    (58880u32, "race"),
    (58936u32, "catch"),
    (58960u32, "finally"),
    (59328u32, "test"),
    (61616u32, "log"),
    (65848u32, "delete"),
];
