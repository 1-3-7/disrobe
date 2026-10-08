#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use super::oodle_encoder::entropy::{Form, MultiStyle};
use super::oodle_encoder::huffman::HuffHeader;
use super::oodle_encoder::tans::TansTable;
use super::oodle_encoder::{Block, BlockPlan, Codec, LzStyle, SubBlock, encode_stream};

pub const FIXTURE_DIR: &str = "forge/oodle";

pub const OODLE_FIXTURES: &[&str] = &[
    "kraken-sub.oodle",
    "kraken-raw-scaled.oodle",
    "kraken-two-sub-blocks.oodle",
    "leviathan-sub.oodle",
    "leviathan-raw-multi-command.oodle",
    "leviathan-lamsub.oodle",
    "leviathan-sub-and-3.oodle",
    "leviathan-o1.oodle",
    "leviathan-sub-and-f-scaled.oodle",
    "mermaid-sub.oodle",
    "mermaid-raw-entropy-near.oodle",
    "kraken-stored-arrays.oodle",
    "entropy-huffman-old-sparse.oodle",
    "entropy-huffman-old-dense.oodle",
    "entropy-huffman-new.oodle",
    "entropy-huffman-two-halves.oodle",
    "entropy-huffman-memset.oodle",
    "entropy-tans-explicit.oodle",
    "entropy-tans-rice.oodle",
    "entropy-rle.oodle",
    "entropy-rle-coded.oodle",
    "entropy-recursive.oodle",
    "entropy-recursive-multi-array.oodle",
    "quantum-stored.oodle",
    "block-uncompressed.oodle",
    "hydra.oodle",
];

struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        let mut x: u64 = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    const fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

const WORDS: &[&str] = &[
    "the", "archive", "stores", "every", "entry", "behind", "a", "block", "header", "and", "each",
    "chunk", "carries", "its", "own", "checksum", "while", "decoder", "reads", "literal", "match",
    "offset", "length", "stream", "from", "both", "ends", "of", "sub", "quantum",
];

pub fn text(seed: u64, len: usize) -> Vec<u8> {
    let mut rng: Rng = Rng(seed | 1);
    let mut out: Vec<u8> = Vec::with_capacity(len + 16);
    while out.len() < len {
        let word: &str = WORDS[rng.below(WORDS.len() as u64) as usize];
        out.extend_from_slice(word.as_bytes());
        out.push(match rng.below(12) {
            0 => b'.',
            1 => b',',
            2 => b'\n',
            _ => b' ',
        });
    }
    out.truncate(len);
    out
}

pub fn records(seed: u64, len: usize) -> Vec<u8> {
    let mut rng: Rng = Rng(seed | 1);
    let mut out: Vec<u8> = Vec::with_capacity(len + 32);
    let mut id: u32 = 1000;
    while out.len() < len {
        id += 1 + rng.below(3) as u32;
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&0x3F80_0000u32.to_le_bytes());
        out.extend_from_slice(&((rng.below(64) as u32) << 8).to_le_bytes());
        out.extend_from_slice(b"VERTEX\0\0");
        out.push(rng.next() as u8);
        out.extend_from_slice(&[0u8; 11]);
    }
    out.truncate(len);
    out
}

pub fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut rng: Rng = Rng(seed | 1);
    (0..len).map(|_| rng.next() as u8).collect()
}

pub fn mixed(seed: u64, len: usize) -> Vec<u8> {
    let mut rng: Rng = Rng(seed | 1);
    let mut out: Vec<u8> = Vec::with_capacity(len + 4096);
    let mut part: u64 = 0;
    while out.len() < len {
        let size: usize = 512 + rng.below(3000) as usize;
        match part % 4 {
            0 => out.extend(text(seed + part, size)),
            1 => out.extend(records(seed + part, size)),
            2 => out.extend(std::iter::repeat_n(0u8, size + 600)),
            _ => {
                let back: usize = out.len().min(70_000);
                let from: usize = out.len() - back;
                let copy: Vec<u8> = out[from..from + size.min(back)].to_vec();
                out.extend(copy);
            }
        }
        part += 1;
    }
    out.truncate(len);
    out
}

fn repeated(seed: u64, len: usize) -> Vec<u8> {
    let unit: Vec<u8> = text(seed, 1500);
    unit.iter().copied().cycle().take(len).collect()
}

fn dna(seed: u64, len: usize) -> Vec<u8> {
    let mut rng: Rng = Rng(seed | 1);
    (0..len)
        .map(|_| match rng.below(10) {
            0..=4 => b'A',
            5..=6 => b'C',
            7..=8 => b'G',
            _ => b'T',
        })
        .collect()
}

fn runs(seed: u64, len: usize) -> Vec<u8> {
    let mut rng: Rng = Rng(seed | 1);
    let mut out: Vec<u8> = Vec::with_capacity(len + 300);
    while out.len() < len {
        let byte: u8 = [0u8, 0xFF, b' ', b'x'][rng.below(4) as usize];
        out.extend(std::iter::repeat_n(byte, 3 + rng.below(200) as usize));
        out.extend(text(rng.next(), rng.below(20) as usize));
    }
    out.truncate(len);
    out
}

pub fn payload_for(name: &str) -> Vec<u8> {
    match name {
        "kraken-sub.oodle" | "leviathan-sub.oodle" => text(1, 24_000),
        "kraken-raw-scaled.oodle" | "leviathan-raw-multi-command.oodle" => records(2, 30_000),
        "kraken-two-sub-blocks.oodle" => mixed(3, 200_000),
        "leviathan-lamsub.oodle" | "leviathan-sub-and-3.oodle" => mixed(4, 20_000),
        "leviathan-o1.oodle" | "leviathan-sub-and-f-scaled.oodle" => records(5, 18_000),
        "mermaid-sub.oodle" => mixed(6, 110_000),
        "mermaid-raw-entropy-near.oodle" => records(7, 90_000),
        "kraken-stored-arrays.oodle"
        | "entropy-huffman-old-sparse.oodle"
        | "entropy-huffman-new.oodle"
        | "entropy-recursive.oodle" => text(8, 6000),
        "entropy-huffman-old-dense.oodle" | "entropy-huffman-two-halves.oodle" => records(9, 6000),
        "entropy-huffman-memset.oodle" => vec![b'A'; 5000],
        "entropy-tans-explicit.oodle" => dna(10, 6000),
        "entropy-tans-rice.oodle" => text(11, 7000),
        "entropy-rle.oodle" | "entropy-rle-coded.oodle" => runs(12, 8000),
        "entropy-recursive-multi-array.oodle" => mixed(13, 9000),
        "quantum-stored.oodle" => noise(14, 3000),
        "block-uncompressed.oodle" => noise(15, 2000),
        "hydra.oodle" => {
            let mut out: Vec<u8> = repeated(16, 3 * 0x4_0000);
            out.extend(std::iter::repeat_n(0x5Au8, 0x4_0000));
            out.extend(noise(17, 1500));
            out
        }
        other => panic!("no Oodle fixture named {other}"),
    }
}

fn lz(codec: Codec, subs: Vec<SubBlock>) -> Vec<BlockPlan> {
    vec![BlockPlan {
        codec,
        block: Block::Quantum(subs),
    }]
}

fn entropy(form: Form) -> Vec<BlockPlan> {
    lz(Codec::Kraken, vec![SubBlock::Entropy(form)])
}

pub fn plans_for(name: &str) -> Vec<BlockPlan> {
    let base: LzStyle = LzStyle::default();
    match name {
        "kraken-sub.oodle" => lz(
            Codec::Kraken,
            vec![SubBlock::Lz {
                mode: 0,
                style: base,
            }],
        ),
        "kraken-raw-scaled.oodle" => lz(
            Codec::Kraken,
            vec![SubBlock::Lz {
                mode: 1,
                style: LzStyle {
                    literals: Form::HuffmanHalves(HuffHeader::New { forced: 2 }),
                    commands: Form::Huffman(HuffHeader::OldSparse),
                    offsets: Form::Tans {
                        table: TansTable::Rice { q: 1 },
                        l_bits: 9,
                    },
                    lengths: Form::Rle,
                    scale: Some(3),
                    ..base
                },
            }],
        ),
        "kraken-two-sub-blocks.oodle" => lz(
            Codec::Kraken,
            vec![
                SubBlock::Lz {
                    mode: 0,
                    style: base.clone(),
                },
                SubBlock::Lz {
                    mode: 1,
                    style: LzStyle {
                        scale: Some(1),
                        max_match: 1 << 16,
                        ..base
                    },
                },
            ],
        ),
        "leviathan-sub.oodle" => lz(
            Codec::Leviathan,
            vec![SubBlock::Lz {
                mode: 0,
                style: base,
            }],
        ),
        "leviathan-raw-multi-command.oodle" => lz(
            Codec::Leviathan,
            vec![SubBlock::Lz {
                mode: 1,
                style: LzStyle {
                    multi_commands: true,
                    ..base
                },
            }],
        ),
        "leviathan-lamsub.oodle" => lz(
            Codec::Leviathan,
            vec![SubBlock::Lz {
                mode: 2,
                style: base,
            }],
        ),
        "leviathan-sub-and-3.oodle" => lz(
            Codec::Leviathan,
            vec![SubBlock::Lz {
                mode: 3,
                style: LzStyle {
                    multi: MultiStyle::Intervals {
                        sources: 3,
                        packed: true,
                    },
                    ..base
                },
            }],
        ),
        "leviathan-o1.oodle" => lz(
            Codec::Leviathan,
            vec![SubBlock::Lz {
                mode: 4,
                style: LzStyle {
                    multi: MultiStyle::Intervals {
                        sources: 5,
                        packed: false,
                    },
                    ..base
                },
            }],
        ),
        "leviathan-sub-and-f-scaled.oodle" => lz(
            Codec::Leviathan,
            vec![SubBlock::Lz {
                mode: 5,
                style: LzStyle {
                    scale: Some(2),
                    multi: MultiStyle::Plain(Form::Stored),
                    ..base
                },
            }],
        ),
        "mermaid-sub.oodle" => lz(
            Codec::Mermaid,
            vec![SubBlock::Lz {
                mode: 0,
                style: LzStyle {
                    far_matches: true,
                    ..base
                },
            }],
        ),
        "mermaid-raw-entropy-near.oodle" => lz(
            Codec::Mermaid,
            vec![SubBlock::Lz {
                mode: 1,
                style: LzStyle {
                    entropy_near_offsets: true,
                    offsets: Form::Huffman(HuffHeader::New { forced: 0 }),
                    ..base
                },
            }],
        ),
        "kraken-stored-arrays.oodle" => lz(
            Codec::Kraken,
            vec![SubBlock::Lz {
                mode: 0,
                style: LzStyle {
                    literals: Form::Stored,
                    commands: Form::Stored,
                    offsets: Form::Stored,
                    lengths: Form::Stored,
                    ..base
                },
            }],
        ),
        "entropy-huffman-old-sparse.oodle" | "entropy-huffman-memset.oodle" => {
            entropy(Form::Huffman(HuffHeader::OldSparse))
        }
        "entropy-huffman-old-dense.oodle" => {
            entropy(Form::Huffman(HuffHeader::OldDense { forced: 2 }))
        }
        "entropy-huffman-new.oodle" => entropy(Form::Huffman(HuffHeader::New { forced: 3 })),
        "entropy-huffman-two-halves.oodle" => {
            entropy(Form::HuffmanHalves(HuffHeader::OldDense { forced: 1 }))
        }
        "entropy-tans-explicit.oodle" => entropy(Form::Tans {
            table: TansTable::Explicit,
            l_bits: 8,
        }),
        "entropy-tans-rice.oodle" => entropy(Form::Tans {
            table: TansTable::Rice { q: 0 },
            l_bits: 11,
        }),
        "entropy-rle.oodle" => entropy(Form::Rle),
        "entropy-rle-coded.oodle" => entropy(Form::RleCodedCommands),
        "entropy-recursive.oodle" => entropy(Form::Recursive(3)),
        "entropy-recursive-multi-array.oodle" => entropy(Form::RecursiveMulti(4)),
        "quantum-stored.oodle" => vec![BlockPlan {
            codec: Codec::Mermaid,
            block: Block::Stored,
        }],
        "block-uncompressed.oodle" => vec![BlockPlan {
            codec: Codec::Leviathan,
            block: Block::Uncompressed,
        }],
        "hydra.oodle" => vec![
            BlockPlan {
                codec: Codec::Kraken,
                block: Block::Quantum(vec![SubBlock::Lz {
                    mode: 0,
                    style: LzStyle {
                        max_match: 1 << 16,
                        ..base.clone()
                    },
                }]),
            },
            BlockPlan {
                codec: Codec::Leviathan,
                block: Block::Quantum(vec![SubBlock::Lz {
                    mode: 0,
                    style: LzStyle {
                        max_match: 1 << 16,
                        ..base.clone()
                    },
                }]),
            },
            BlockPlan {
                codec: Codec::Mermaid,
                block: Block::Quantum(vec![SubBlock::Lz {
                    mode: 1,
                    style: LzStyle {
                        max_match: 1 << 16,
                        ..base
                    },
                }]),
            },
            BlockPlan {
                codec: Codec::Leviathan,
                block: Block::Memset,
            },
            BlockPlan {
                codec: Codec::Kraken,
                block: Block::Uncompressed,
            },
        ],
        other => panic!("no Oodle fixture plan named {other}"),
    }
}

pub fn stream_for(name: &str) -> Vec<u8> {
    encode_stream(&payload_for(name), &plans_for(name))
}

pub fn role(name: &str) -> &'static str {
    match name {
        "kraken-sub.oodle" => "Kraken LZ sub-block, delta literals, classic offsets",
        "kraken-raw-scaled.oodle" => {
            "Kraken LZ sub-block, raw literals, offsets scaled by 3 with low bytes, two-half Huffman literals, TANS offsets, RLE lengths"
        }
        "kraken-two-sub-blocks.oodle" => {
            "Kraken quantum of two 128 KiB sub-blocks (delta then raw, scale 1), long lengths"
        }
        "leviathan-sub.oodle" => "Leviathan literal mode 0 (sub)",
        "leviathan-raw-multi-command.oodle" => {
            "Leviathan literal mode 1 (raw) with eight command streams in a three-source multi-array"
        }
        "leviathan-lamsub.oodle" => "Leviathan literal mode 2 (lamsub), plain multi-array",
        "leviathan-sub-and-3.oodle" => {
            "Leviathan literal mode 3 (sub and 3), packed-interval multi-array"
        }
        "leviathan-o1.oodle" => "Leviathan literal mode 4 (o1), interval multi-array",
        "leviathan-sub-and-f-scaled.oodle" => {
            "Leviathan literal mode 5 (sub and 15), offsets scaled by 2"
        }
        "mermaid-sub.oodle" => {
            "Mermaid delta literals over two 64 KiB halves with near and far offsets"
        }
        "mermaid-raw-entropy-near.oodle" => "Mermaid raw literals with entropy-coded near offsets",
        "kraken-stored-arrays.oodle" => "Kraken LZ sub-block whose four streams are stored arrays",
        "entropy-huffman-old-sparse.oodle" => "entropy-only sub-block, Huffman old sparse header",
        "entropy-huffman-old-dense.oodle" => "entropy-only sub-block, Huffman old dense header",
        "entropy-huffman-new.oodle" => {
            "entropy-only sub-block, Huffman new header with three Rice extra bits"
        }
        "entropy-huffman-two-halves.oodle" => "entropy-only sub-block, two-half Huffman",
        "entropy-huffman-memset.oodle" => "entropy-only sub-block, single-symbol Huffman",
        "entropy-tans-explicit.oodle" => "entropy-only sub-block, TANS with explicit weights",
        "entropy-tans-rice.oodle" => "entropy-only sub-block, TANS with Rice-coded weights",
        "entropy-rle.oodle" => "entropy-only sub-block, RLE with raw commands",
        "entropy-rle-coded.oodle" => "entropy-only sub-block, RLE with Huffman-coded commands",
        "entropy-recursive.oodle" => "entropy-only sub-block, recursive array of three parts",
        "entropy-recursive-multi-array.oodle" => {
            "entropy-only sub-block, recursive multi-array with four sources"
        }
        "quantum-stored.oodle" => "stored quantum",
        "block-uncompressed.oodle" => "uncompressed block",
        "hydra.oodle" => {
            "five blocks switching decoders: Kraken, Leviathan, Mermaid quanta, a memset quantum and an uncompressed tail"
        }
        other => panic!("no Oodle fixture role for {other}"),
    }
}
