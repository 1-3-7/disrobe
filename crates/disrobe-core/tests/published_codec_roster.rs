#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_core::codec::framed::{xxencode, yenc_encode};
use disrobe_core::{CodecScheme, DecodeError, codec_decode};

const PUBLISHED_SCHEME_COUNT: usize = 17;

const CHAIN_DOC: &str = "docs/src/chain.md";
const CODEC_ROW_MARKER: &str = "| Encoding and cipher reversal |";

const ROUND_TRIP_PLAINTEXT: &[u8] = b"disrobe codec roster";

const BASE122_VECTOR_HEX: &str = "34192d46633c582031182e3629446432101d6d77133148";
const BASE122_PLAINTEXT: &[u8] = b"hello, base122 world";

const BASE58_BITCOIN_VECTOR_HEX: &str = "3251387657335447726a34583274344e71327a793677487a6f6a7533";
const BASE58_RIPPLE_VECTOR_HEX: &str = "7051337657735447696a68587074683471707a796141487a6f6a7573";
const BASE62_VECTOR_HEX: &str = "454b486670576c4477694c685a734e475556796236744b7a636773";
const BASE45_VECTOR_HEX: &str = "415643595145543345445a435550433656432d4e43304c45205145352443";
const BASE91_VECTOR_HEX: &str = "6d614f33693e61652479372639387b692279633d5b5b724e48";
const BASE92_VECTOR_HEX: &str = "453e323f6978613e3e6f68776f4131302d473d466b44336f2a";
const ASCII85_VECTOR_HEX: &str = "41382d2b2a44646d39234072476d68406a236631462a287536";
const Z85_VECTOR_HEX: &str = "776e6361397a5e296f32764043293f763c322f67423937236c";
const UUENCODE_VECTOR_HEX: &str = "626567696e20363434207061796c6f61642e62696e0a34392645533c465d42393221433b563145385221523b572d54393728200a600a656e640a";
const PERCENT_URL_VECTOR_HEX: &str = "646973726f6265253230636f646563253230726f73746572";

#[derive(Debug, Clone, Copy)]
struct PublishedScheme {
    scheme: CodecScheme,
    label: &'static str,
    doc_token: &'static str,
}

const PUBLISHED: [PublishedScheme; PUBLISHED_SCHEME_COUNT] = [
    PublishedScheme {
        scheme: CodecScheme::Base58Bitcoin,
        label: "base58:bitcoin",
        doc_token: "base58/62/45/91/92/122",
    },
    PublishedScheme {
        scheme: CodecScheme::Base58Ripple,
        label: "base58:ripple",
        doc_token: "base58/62/45/91/92/122",
    },
    PublishedScheme {
        scheme: CodecScheme::Base62,
        label: "base62",
        doc_token: "base58/62/45/91/92/122",
    },
    PublishedScheme {
        scheme: CodecScheme::Base45,
        label: "base45",
        doc_token: "base58/62/45/91/92/122",
    },
    PublishedScheme {
        scheme: CodecScheme::Base91,
        label: "base91",
        doc_token: "base58/62/45/91/92/122",
    },
    PublishedScheme {
        scheme: CodecScheme::Base92,
        label: "base92",
        doc_token: "base58/62/45/91/92/122",
    },
    PublishedScheme {
        scheme: CodecScheme::Base122,
        label: "base122",
        doc_token: "base58/62/45/91/92/122",
    },
    PublishedScheme {
        scheme: CodecScheme::Ascii85,
        label: "ascii85",
        doc_token: "ascii85/Z85",
    },
    PublishedScheme {
        scheme: CodecScheme::Z85,
        label: "z85",
        doc_token: "ascii85/Z85",
    },
    PublishedScheme {
        scheme: CodecScheme::UuEncode,
        label: "uuencode",
        doc_token: "uuencode/xxencode/yEnc",
    },
    PublishedScheme {
        scheme: CodecScheme::XxEncode,
        label: "xxencode",
        doc_token: "uuencode/xxencode/yEnc",
    },
    PublishedScheme {
        scheme: CodecScheme::YEnc,
        label: "yenc",
        doc_token: "uuencode/xxencode/yEnc",
    },
    PublishedScheme {
        scheme: CodecScheme::PercentUrl,
        label: "percent-url",
        doc_token: "percent-URL",
    },
    PublishedScheme {
        scheme: CodecScheme::HtmlEntity,
        label: "html-entity",
        doc_token: "HTML entity",
    },
    PublishedScheme {
        scheme: CodecScheme::Punycode,
        label: "punycode",
        doc_token: "Punycode",
    },
    PublishedScheme {
        scheme: CodecScheme::Base64Standard,
        label: "base64:standard",
        doc_token: "base64/85/32/16",
    },
    PublishedScheme {
        scheme: CodecScheme::Base64Url,
        label: "base64:url",
        doc_token: "base64/85/32/16",
    },
];

const fn published_label(scheme: CodecScheme) -> &'static str {
    match scheme {
        CodecScheme::Base58Bitcoin => "base58:bitcoin",
        CodecScheme::Base58Ripple => "base58:ripple",
        CodecScheme::Base62 => "base62",
        CodecScheme::Base45 => "base45",
        CodecScheme::Base91 => "base91",
        CodecScheme::Base92 => "base92",
        CodecScheme::Base122 => "base122",
        CodecScheme::Ascii85 => "ascii85",
        CodecScheme::Z85 => "z85",
        CodecScheme::UuEncode => "uuencode",
        CodecScheme::XxEncode => "xxencode",
        CodecScheme::YEnc => "yenc",
        CodecScheme::PercentUrl => "percent-url",
        CodecScheme::HtmlEntity => "html-entity",
        CodecScheme::Punycode => "punycode",
        CodecScheme::Base64Standard => "base64:standard",
        CodecScheme::Base64Url => "base64:url",
    }
}

fn unhex(text: &str) -> Vec<u8> {
    let bytes: &[u8] = text.as_bytes();
    assert!(
        bytes.len().is_multiple_of(2),
        "a reference vector must be a whole number of bytes: {text}"
    );
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() / 2);
    let mut index: usize = 0;
    while index < bytes.len() {
        let Some(pair): Option<&str> = text.get(index..index.saturating_add(2)) else {
            panic!("reference vector {text} splits mid-character at {index}")
        };
        let Ok(byte): Result<u8, core::num::ParseIntError> = u8::from_str_radix(pair, 16) else {
            panic!("reference vector {text} carries a non-hex pair `{pair}`")
        };
        out.push(byte);
        index = index.saturating_add(2);
    }
    out
}

#[derive(Debug, Clone)]
struct Vector {
    encoded: Vec<u8>,
    plaintext: Vec<u8>,
    basis: &'static str,
}

fn vector_for(scheme: CodecScheme) -> Vector {
    let plain: Vec<u8> = ROUND_TRIP_PLAINTEXT.to_vec();
    let round_trip: &str = "an encoding produced by this crate's own encoder for the same scheme";
    match scheme {
        CodecScheme::Base58Bitcoin => Vector {
            encoded: unhex(BASE58_BITCOIN_VECTOR_HEX),
            plaintext: plain,
            basis: "the base58 2.1.1 PyPI package, `b58encode` on the bitcoin alphabet",
        },
        CodecScheme::Base58Ripple => Vector {
            encoded: unhex(BASE58_RIPPLE_VECTOR_HEX),
            plaintext: plain,
            basis: "the base58 2.1.1 PyPI package, `b58encode` on `RIPPLE_ALPHABET`",
        },
        CodecScheme::Base62 => Vector {
            encoded: unhex(BASE62_VECTOR_HEX),
            plaintext: plain,
            basis: "the pybase62 1.0.0 PyPI package, `encodebytes`",
        },
        CodecScheme::Base45 => Vector {
            encoded: unhex(BASE45_VECTOR_HEX),
            plaintext: plain,
            basis: "the base45 0.4.4 PyPI package, `b45encode`, which implements RFC 9285",
        },
        CodecScheme::Base91 => Vector {
            encoded: unhex(BASE91_VECTOR_HEX),
            plaintext: plain,
            basis: "the base91 1.0.1 PyPI package, `encode`",
        },
        CodecScheme::Base92 => Vector {
            encoded: unhex(BASE92_VECTOR_HEX),
            plaintext: plain,
            basis: "the base92 2.0.0 PyPI package, `b92encode`",
        },
        CodecScheme::Base122 => Vector {
            encoded: unhex(BASE122_VECTOR_HEX),
            plaintext: BASE122_PLAINTEXT.to_vec(),
            basis: "the base122 reference encoder, recorded as an independent vector in \
                    src/codec/alphabets.rs",
        },
        CodecScheme::Ascii85 => Vector {
            encoded: unhex(ASCII85_VECTOR_HEX),
            plaintext: plain,
            basis: "CPython 3.13 `base64.a85encode`",
        },
        CodecScheme::Z85 => Vector {
            encoded: unhex(Z85_VECTOR_HEX),
            plaintext: plain,
            basis: "pyzmq 27.1.0 `zmq.utils.z85.encode`, the ZeroMQ reference implementation",
        },
        CodecScheme::UuEncode => Vector {
            encoded: unhex(UUENCODE_VECTOR_HEX),
            plaintext: plain,
            basis: "CPython 3.13 `binascii.b2a_uu` inside the standard begin/end framing",
        },
        CodecScheme::XxEncode => Vector {
            encoded: xxencode(&plain, "payload.bin").into_bytes(),
            plaintext: plain,
            basis: round_trip,
        },
        CodecScheme::YEnc => Vector {
            encoded: yenc_encode(&plain, "payload.bin"),
            plaintext: plain,
            basis: round_trip,
        },
        CodecScheme::PercentUrl => Vector {
            encoded: unhex(PERCENT_URL_VECTOR_HEX),
            plaintext: plain,
            basis: "CPython 3.13 `urllib.parse.quote` with an empty safe set",
        },
        CodecScheme::HtmlEntity => Vector {
            encoded: b"&lt;script&gt;&#x41;&amp;".to_vec(),
            plaintext: b"<script>A&".to_vec(),
            basis: "the HTML named and numeric character reference syntax",
        },
        CodecScheme::Punycode => Vector {
            encoded: b"xn--bcher-kva".to_vec(),
            plaintext: "b\u{fc}cher".as_bytes().to_vec(),
            basis: "the RFC 3492 punycode algorithm",
        },
        CodecScheme::Base64Standard => Vector {
            encoded: b"PDw/Pz8+Pg==".to_vec(),
            plaintext: b"<<???>>".to_vec(),
            basis: "the RFC 4648 standard alphabet, which uses `+` and `/`",
        },
        CodecScheme::Base64Url => Vector {
            encoded: b"PDw_Pz8-Pg==".to_vec(),
            plaintext: b"<<???>>".to_vec(),
            basis: "the RFC 4648 url-safe alphabet, which uses `-` and `_`",
        },
    }
}

fn repo_root() -> PathBuf {
    let manifest: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(root): Option<&Path> = manifest.parent().and_then(Path::parent) else {
        panic!(
            "the published codec roster is stated in {CHAIN_DOC}, two directories above {}, so a \
             manifest path with no grandparent leaves the roster checked against nothing",
            manifest.display()
        )
    };
    root.to_path_buf()
}

fn codec_row() -> String {
    let path: PathBuf = repo_root().join(CHAIN_DOC);
    let doc: String = fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{CHAIN_DOC} is the surface that publishes which encodings disrobe reverses, so a run \
             that cannot read it must fail rather than report a green that checked no document: \
             {error} at {}",
            path.display()
        )
    });
    let found: Option<&str> = doc
        .lines()
        .find(|line: &&str| line.trim_start().starts_with(CODEC_ROW_MARKER));
    let Some(row): Option<&str> = found else {
        panic!(
            "{CHAIN_DOC} no longer carries a row beginning `{CODEC_ROW_MARKER}`, so the published \
             encoding roster cannot be located and every scheme this crate carries is bound to \
             nothing"
        )
    };
    row.to_owned()
}

fn roster_labels() -> BTreeSet<String> {
    CodecScheme::all()
        .iter()
        .map(|scheme: &CodecScheme| published_label(*scheme).to_owned())
        .collect()
}

fn published_labels() -> BTreeSet<String> {
    PUBLISHED
        .into_iter()
        .map(|row: PublishedScheme| row.label.to_owned())
        .collect()
}

#[test]
fn the_published_roster_is_exactly_the_scheme_set_the_cascade_walks() {
    assert_eq!(
        PUBLISHED.len(),
        PUBLISHED_SCHEME_COUNT,
        "the published roster is the denominator the {CHAIN_DOC} encoding row enumerates, so it is \
         pinned by equality rather than counted from whatever this table happens to hold"
    );
    assert_eq!(
        CodecScheme::all().len(),
        PUBLISHED_SCHEME_COUNT,
        "`CodecScheme::all()` is the set the blind cascade and every peel walk, and it carries {} \
         schemes against the {PUBLISHED_SCHEME_COUNT} the roster publishes; a scheme dropped from \
         this list stops being tried while {CHAIN_DOC} still names it",
        CodecScheme::all().len()
    );

    assert_eq!(
        roster_labels(),
        published_labels(),
        "the schemes `CodecScheme::all()` walks and the schemes the published roster names are \
         different sets, so a swap that preserved the count would leave {CHAIN_DOC} describing a \
         decode that no longer runs"
    );

    for row in PUBLISHED {
        assert_eq!(
            published_label(row.scheme),
            row.label,
            "the exhaustive mapping and the published roster disagree on how {:?} is spelled",
            row.scheme
        );
        assert_eq!(
            row.scheme.label(),
            row.label,
            "{:?} reports itself as `{}` in a chain stage name while the roster publishes `{}`",
            row.scheme,
            row.scheme.label(),
            row.label
        );
    }
}

#[test]
fn the_chain_guide_names_every_scheme_this_crate_reverses() {
    let row: String = codec_row();
    for entry in PUBLISHED {
        assert!(
            row.contains(entry.doc_token),
            "{:?} is in the roster the cascade walks, and {CHAIN_DOC} publishes it under the token \
             `{}`, but that token is absent from the encoding row: {row}",
            entry.scheme,
            entry.doc_token
        );
    }

    let tokens: BTreeSet<&'static str> = PUBLISHED
        .into_iter()
        .map(|entry: PublishedScheme| entry.doc_token)
        .collect();
    assert!(
        !tokens.is_empty(),
        "the roster must name at least one published token, otherwise the containment loop above \
         checks nothing"
    );
    assert!(
        !row.contains("base32"),
        "the encoding row now names base32 as a scheme of its own, but `CodecScheme` carries none, \
         so the roster and the page have diverged: {row}"
    );
}

#[test]
fn every_published_scheme_decodes_its_vector_back_to_the_plaintext() {
    for entry in PUBLISHED {
        let vector: Vector = vector_for(entry.scheme);
        assert!(
            !vector.encoded.is_empty(),
            "{:?} produced an empty vector, so the decode below would prove nothing",
            entry.scheme
        );
        assert_ne!(
            vector.encoded, vector.plaintext,
            "{:?} produced a vector identical to its plaintext, so a decoder that returned its \
             input unchanged would pass",
            entry.scheme
        );

        let decoded: Result<Vec<u8>, DecodeError> = codec_decode(&vector.encoded, entry.scheme);
        let Ok(bytes): Result<Vec<u8>, DecodeError> = decoded else {
            panic!(
                "{CHAIN_DOC} publishes `{}` as reversed, but decoding a vector taken from {} \
                 failed: {decoded:?}",
                entry.label, vector.basis
            )
        };
        assert_eq!(
            bytes, vector.plaintext,
            "{:?} decoded its vector to something other than the plaintext {} describes",
            entry.scheme, vector.basis
        );
    }
}

#[test]
fn no_scheme_stands_in_for_another_on_the_same_vector() {
    for entry in PUBLISHED {
        let vector: Vector = vector_for(entry.scheme);
        for other in PUBLISHED {
            if other.scheme == entry.scheme {
                continue;
            }
            let decoded: Result<Vec<u8>, DecodeError> = codec_decode(&vector.encoded, other.scheme);
            assert!(
                decoded.as_deref() != Ok(vector.plaintext.as_slice()),
                "`{}` recovers the plaintext from a vector the roster attributes to `{}`, so one \
                 scheme could be deleted and its neighbour would keep the membership check green",
                other.label,
                entry.label
            );
        }
    }
}
