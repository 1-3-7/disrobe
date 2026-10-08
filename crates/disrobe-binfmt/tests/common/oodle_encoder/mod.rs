#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

pub mod bits;
pub mod entropy;
pub mod huffman;
pub mod kraken;
pub mod leviathan;
pub mod lz;
pub mod mermaid;
pub mod tans;

use entropy::{Form, MultiStyle, encode};
use huffman::HuffHeader;

pub const BLOCK_SPAN: usize = 0x4_0000;
pub const SUB_BLOCK_SPAN: usize = 0x2_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Kraken,
    Mermaid,
    Leviathan,
}

impl Codec {
    pub const fn code(self) -> u8 {
        match self {
            Self::Kraken => 6,
            Self::Mermaid => 10,
            Self::Leviathan => 12,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LzStyle {
    pub literals: Form,
    pub commands: Form,
    pub offsets: Form,
    pub lengths: Form,
    pub scale: Option<u32>,
    pub max_match: usize,
    pub multi: MultiStyle,
    pub multi_commands: bool,
    pub entropy_near_offsets: bool,
    pub far_matches: bool,
}

impl Default for LzStyle {
    fn default() -> Self {
        Self {
            literals: Form::Huffman(HuffHeader::New { forced: 1 }),
            commands: Form::Huffman(HuffHeader::OldDense { forced: 0 }),
            offsets: Form::Huffman(HuffHeader::OldSparse),
            lengths: Form::Stored,
            scale: None,
            max_match: 4096,
            multi: MultiStyle::Plain(Form::Huffman(HuffHeader::New { forced: 0 })),
            multi_commands: false,
            entropy_near_offsets: false,
            far_matches: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubBlock {
    Raw,
    Entropy(Form),
    Lz { mode: u32, style: LzStyle },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    Uncompressed,
    Memset,
    Stored,
    Quantum(Vec<SubBlock>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockPlan {
    pub codec: Codec,
    pub block: Block,
}

fn sub_block(codec: Codec, window: &[u8], start: usize, end: usize, plan: &SubBlock) -> Vec<u8> {
    let count: usize = end - start;
    let raw = || {
        let mut out: Vec<u8> = (0x80_0000u32 | count as u32).to_be_bytes()[1..].to_vec();
        out.extend_from_slice(&window[start..end]);
        out
    };
    match plan {
        SubBlock::Raw => raw(),
        SubBlock::Entropy(form) => encode(&window[start..end], form, true).unwrap_or_else(raw),
        SubBlock::Lz { mode, style } => {
            let body: Vec<u8> = match codec {
                Codec::Kraken => kraken::encode_sub_block(window, start, end, *mode == 0, style),
                Codec::Leviathan => leviathan::encode_sub_block(window, start, end, *mode, style),
                Codec::Mermaid => mermaid::encode_sub_block(window, start, end, *mode == 0, style),
            };
            if body.len() >= count || body.len() > 0x7_FFFF {
                return raw();
            }
            let header: u32 = 0x80_0000 | (mode << 19) | body.len() as u32;
            let mut out: Vec<u8> = header.to_be_bytes()[1..].to_vec();
            out.extend(body);
            out
        }
    }
}

pub fn encode_stream(data: &[u8], plans: &[BlockPlan]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for (index, start) in (0..data.len()).step_by(BLOCK_SPAN).enumerate() {
        let end: usize = (start + BLOCK_SPAN).min(data.len());
        let plan: &BlockPlan = &plans[index % plans.len()];
        let uncompressed: bool = plan.block == Block::Uncompressed;
        out.push(0x8C | if uncompressed { 0x40 } else { 0 });
        out.push(plan.codec.code());
        match &plan.block {
            Block::Uncompressed => out.extend_from_slice(&data[start..end]),
            Block::Memset => {
                assert!(
                    data[start..end].iter().all(|&b: &u8| b == data[start]),
                    "a memset quantum needs one repeated byte"
                );
                out.extend_from_slice(&[0x07, 0xFF, 0xFF, data[start]]);
            }
            Block::Stored => {
                out.extend_from_slice(&((end - start - 1) as u32).to_be_bytes()[1..]);
                out.extend_from_slice(&data[start..end]);
            }
            Block::Quantum(subs) => {
                let window: &[u8] = &data[..end];
                let mut body: Vec<u8> = Vec::new();
                for (i, sub_start) in (start..end).step_by(SUB_BLOCK_SPAN).enumerate() {
                    let sub_end: usize = (sub_start + SUB_BLOCK_SPAN).min(end);
                    body.extend(sub_block(
                        plan.codec,
                        window,
                        sub_start,
                        sub_end,
                        &subs[i % subs.len()],
                    ));
                }
                if body.len() >= end - start {
                    out.extend_from_slice(&((end - start - 1) as u32).to_be_bytes()[1..]);
                    out.extend_from_slice(&data[start..end]);
                } else {
                    out.extend_from_slice(&((body.len() - 1) as u32).to_be_bytes()[1..]);
                    out.extend(body);
                }
            }
        }
    }
    out
}

pub fn lz_stream(codec: Codec, mode: u32, style: LzStyle, data: &[u8]) -> Vec<u8> {
    encode_stream(
        data,
        &[BlockPlan {
            codec,
            block: Block::Quantum(vec![SubBlock::Lz { mode, style }]),
        }],
    )
}
