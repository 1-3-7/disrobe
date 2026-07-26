use crate::error::{Error, Result};

const THRESHOLD: usize = 3;
const MAXMATCH: usize = 256;
const DICBIT: u32 = 13;
const DICSIZ: usize = 1 << DICBIT;
const N_CHAR: usize = 256 + 60 - THRESHOLD + 1;
const TREESIZE_C: usize = N_CHAR * 2;
const TREESIZE_P: usize = 128 * 2;
const TREESIZE: usize = TREESIZE_C + TREESIZE_P;
const ROOT_C: usize = 0;
const ROOT_P: usize = TREESIZE_C;
const N_MAX: usize = 286;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynMethod {
    Lh2,
    Lh3,
}

struct BitReader<'a> {
    src: &'a [u8],
    pos: usize,
    bitbuf: u16,
    subbitbuf: u8,
    bitcount: u32,
}

impl<'a> BitReader<'a> {
    fn new(src: &'a [u8]) -> Self {
        let mut reader: Self = Self {
            src,
            pos: 0,
            bitbuf: 0,
            subbitbuf: 0,
            bitcount: 0,
        };
        reader.fill(16);
        reader
    }

    fn fill(&mut self, mut n: u32) {
        while n > self.bitcount {
            n -= self.bitcount;
            self.bitbuf = (self.bitbuf << self.bitcount)
                | u16::from(shr_u8(self.subbitbuf, 8 - self.bitcount));
            self.subbitbuf = self.src.get(self.pos).copied().map_or(0, |value: u8| value);
            if self.pos < self.src.len() {
                self.pos += 1;
            }
            self.bitcount = 8;
        }
        self.bitcount -= n;
        self.bitbuf = (self.bitbuf << n) | u16::from(shr_u8(self.subbitbuf, 8 - n));
        self.subbitbuf = shl_u8(self.subbitbuf, n);
    }

    const fn peek(&self, n: u32) -> u16 {
        self.bitbuf >> (16 - n)
    }

    fn get(&mut self, n: u32) -> u16 {
        if n == 0 {
            return 0;
        }
        let value: u16 = self.bitbuf >> (16 - n);
        self.fill(n);
        value
    }
}

const fn shr_u8(value: u8, shift: u32) -> u8 {
    if shift >= 8 { 0 } else { value >> shift }
}

const fn shl_u8(value: u8, shift: u32) -> u8 {
    if shift >= 8 { 0 } else { value << shift }
}

struct DynTree {
    child: [i32; TREESIZE],
    parent: [u16; TREESIZE],
    block: [u16; TREESIZE],
    edge: [u16; TREESIZE],
    stock: [u16; TREESIZE],
    node: [u16; TREESIZE / 2],
    freq: [u16; TREESIZE],
    total_p: u16,
    avail: usize,
    most_p: usize,
    nn: usize,
    nextcount: u64,
    n1: usize,
}

const N1_C: usize = if N_MAX > 256 + MAXMATCH - THRESHOLD {
    512
} else {
    N_MAX - 1
};

impl DynTree {
    const fn new() -> Self {
        Self {
            child: [0; TREESIZE],
            parent: [0; TREESIZE],
            block: [0; TREESIZE],
            edge: [0; TREESIZE],
            stock: [0; TREESIZE],
            node: [0; TREESIZE / 2],
            freq: [0; TREESIZE],
            total_p: 0,
            avail: 0,
            most_p: 0,
            nn: 0,
            nextcount: 0,
            n1: 0,
        }
    }

    fn start_c(&mut self) {
        self.n1 = N1_C;
        for i in 0..TREESIZE_C {
            self.stock[i] = i as u16;
            self.block[i] = 0;
        }
        let mut j: usize = N_MAX * 2 - 2;
        for i in 0..N_MAX {
            self.freq[j] = 1;
            self.child[j] = !(i as i32);
            self.node[i] = j as u16;
            self.block[j] = 1;
            j -= 1;
        }
        self.avail = 2;
        self.edge[1] = (N_MAX - 1) as u16;
        let mut i: usize = N_MAX * 2 - 2;
        j = N_MAX - 2;
        loop {
            let f: u16 = self.freq[i] + self.freq[i - 1];
            self.freq[j] = f;
            self.child[j] = i as i32;
            self.parent[i] = j as u16;
            self.parent[i - 1] = j as u16;
            if f == self.freq[j + 1] {
                self.block[j] = self.block[j + 1];
            } else {
                self.block[j] = self.stock[self.avail];
                self.avail += 1;
            }
            self.edge[self.block[j] as usize] = j as u16;
            if j == 0 {
                break;
            }
            i -= 2;
            j -= 1;
        }
    }

    const fn start_p(&mut self) {
        self.freq[ROOT_P] = 1;
        self.child[ROOT_P] = !(N_CHAR as i32);
        self.node[N_CHAR] = ROOT_P as u16;
        self.block[ROOT_P] = self.stock[self.avail];
        self.avail += 1;
        self.edge[self.block[ROOT_P] as usize] = ROOT_P as u16;
        self.most_p = ROOT_P;
        self.total_p = 0;
        self.nn = 1 << DICBIT;
        self.nextcount = 64;
    }

    fn reconst(&mut self, start: usize, end: usize) {
        let lo: isize = start as isize;
        let hi: isize = end as isize;
        let mut dst: isize = lo;
        let mut blk: isize = 0;
        {
            let mut idx: isize = lo;
            while idx < hi {
                let child: i32 = self.child[idx as usize];
                if child < 0 {
                    self.freq[dst as usize] = self.freq[idx as usize].div_ceil(2);
                    self.child[dst as usize] = child;
                    dst += 1;
                }
                blk = i32::from(self.block[idx as usize]) as isize;
                if self.edge[blk as usize] as isize == idx {
                    self.avail -= 1;
                    self.stock[self.avail] = blk as u16;
                }
                idx += 1;
            }
        }
        dst -= 1;
        let mut idx: isize = hi - 1;
        let mut pair: isize = hi - 2;
        while idx >= lo {
            while idx >= pair {
                self.freq[idx as usize] = self.freq[dst as usize];
                self.child[idx as usize] = self.child[dst as usize];
                idx -= 1;
                dst -= 1;
            }
            let merged: u16 = self.freq[pair as usize] + self.freq[(pair + 1) as usize];
            let mut floor: isize = lo;
            while merged < self.freq[floor as usize] {
                floor += 1;
            }
            while dst >= floor {
                self.freq[idx as usize] = self.freq[dst as usize];
                self.child[idx as usize] = self.child[dst as usize];
                idx -= 1;
                dst -= 1;
            }
            self.freq[idx as usize] = merged;
            self.child[idx as usize] = (pair + 1) as i32;
            idx -= 1;
            pair -= 2;
        }
        let mut prev_freq: u16 = 0;
        for idx in start..end {
            let child: i32 = self.child[idx];
            if child < 0 {
                self.node[(!child) as usize] = idx as u16;
            } else {
                self.parent[child as usize] = idx as u16;
                self.parent[(child as usize) - 1] = idx as u16;
            }
            let cur_freq: u16 = self.freq[idx];
            if cur_freq == prev_freq {
                self.block[idx] = blk as u16;
            } else {
                blk = self.stock[self.avail] as isize;
                self.avail += 1;
                self.block[idx] = blk as u16;
                self.edge[blk as usize] = idx as u16;
                prev_freq = cur_freq;
            }
        }
    }

    const fn swap_inc(&mut self, mut node: usize) -> usize {
        let blk: usize = self.block[node] as usize;
        let leader: usize = self.edge[blk] as usize;
        if leader != node {
            let child_node: i32 = self.child[node];
            let child_leader: i32 = self.child[leader];
            self.child[node] = child_leader;
            self.child[leader] = child_node;
            if child_node >= 0 {
                self.parent[child_node as usize] = leader as u16;
                self.parent[(child_node as usize) - 1] = leader as u16;
            } else {
                self.node[(!child_node) as usize] = leader as u16;
            }
            if child_leader >= 0 {
                self.parent[child_leader as usize] = node as u16;
                self.parent[(child_leader as usize) - 1] = node as u16;
            } else {
                self.node[(!child_leader) as usize] = node as u16;
            }
            node = leader;
            self.swap_inc_adjust(node, blk);
        } else if blk == self.block[node + 1] as usize {
            self.swap_inc_adjust(node, blk);
        } else {
            self.freq[node] += 1;
            if self.freq[node] == self.freq[node - 1] {
                self.avail -= 1;
                self.stock[self.avail] = blk as u16;
                self.block[node] = self.block[node - 1];
            }
        }
        self.parent[node] as usize
    }

    const fn swap_inc_adjust(&mut self, node: usize, blk: usize) {
        self.edge[blk] += 1;
        self.freq[node] += 1;
        if self.freq[node] == self.freq[node - 1] {
            self.block[node] = self.block[node - 1];
        } else {
            self.block[node] = self.stock[self.avail];
            self.avail += 1;
            self.edge[self.block[node] as usize] = node as u16;
        }
    }

    fn update_c(&mut self, sym: usize) {
        if self.freq[ROOT_C] == 0x8000 {
            self.reconst(0, N_MAX * 2 - 1);
        }
        self.freq[ROOT_C] += 1;
        let mut node: usize = self.node[sym] as usize;
        loop {
            node = self.swap_inc(node);
            if node == ROOT_C {
                break;
            }
        }
    }

    fn update_p(&mut self, sym: usize) {
        if self.total_p == 0x8000 {
            self.reconst(ROOT_P, self.most_p + 1);
            self.total_p = self.freq[ROOT_P];
            self.freq[ROOT_P] = 0xffff;
        }
        let mut node: usize = self.node[sym + N_CHAR] as usize;
        while node != ROOT_P {
            node = self.swap_inc(node);
        }
        self.total_p += 1;
    }

    fn make_new_node(&mut self, sym: usize) {
        let kept: usize = self.most_p + 1;
        let fresh: usize = kept + 1;
        let moved: i32 = self.child[self.most_p];
        self.child[kept] = moved;
        self.node[(!moved) as usize] = kept as u16;
        self.child[fresh] = !((sym + N_CHAR) as i32);
        self.child[self.most_p] = fresh as i32;
        self.freq[kept] = self.freq[self.most_p];
        self.freq[fresh] = 0;
        self.block[kept] = self.block[self.most_p];
        if self.most_p == ROOT_P {
            self.freq[ROOT_P] = 0xffff;
            self.edge[self.block[ROOT_P] as usize] += 1;
        }
        self.parent[kept] = self.most_p as u16;
        self.parent[fresh] = self.most_p as u16;
        self.block[fresh] = self.stock[self.avail];
        self.avail += 1;
        self.edge[self.block[fresh] as usize] = fresh as u16;
        self.node[sym + N_CHAR] = fresh as u16;
        self.most_p = fresh;
        self.update_p(sym);
    }

    fn decode_c(&mut self, reader: &mut BitReader<'_>) -> usize {
        let mut node: i32 = self.child[ROOT_C];
        let mut buf: u16 = reader.bitbuf;
        let mut cnt: u32 = 0;
        loop {
            let bit: usize = usize::from(buf & 0x8000 != 0);
            node = self.child[(node as usize) - bit];
            buf <<= 1;
            cnt += 1;
            if cnt == 16 {
                reader.fill(16);
                buf = reader.bitbuf;
                cnt = 0;
            }
            if node <= 0 {
                break;
            }
        }
        reader.fill(cnt);
        let sym: usize = (!node) as usize;
        self.update_c(sym);
        if sym == self.n1 {
            sym + usize::from(reader.get(8))
        } else {
            sym
        }
    }

    fn decode_p_dyn(&mut self, reader: &mut BitReader<'_>, decode_count: u64) -> usize {
        while decode_count > self.nextcount {
            let arg: usize = (self.nextcount / 64) as usize;
            self.make_new_node(arg);
            self.nextcount += 64;
            if self.nextcount as usize >= self.nn {
                self.nextcount = u64::from(u32::MAX);
            }
        }
        let mut node: i32 = self.child[ROOT_P];
        let mut buf: u16 = reader.bitbuf;
        let mut cnt: u32 = 0;
        while node > 0 {
            let bit: usize = usize::from(buf & 0x8000 != 0);
            node = self.child[(node as usize) - bit];
            buf <<= 1;
            cnt += 1;
            if cnt == 16 {
                reader.fill(16);
                buf = reader.bitbuf;
                cnt = 0;
            }
        }
        reader.fill(cnt);
        let sym: usize = ((!node) as usize) - N_CHAR;
        self.update_p(sym);
        (sym << 6) + usize::from(reader.get(6))
    }
}

const NP: usize = 8 * 1024 / 64;
const N1: usize = 286;
const EXTRABITS: u32 = 8;
const BUFBITS: u32 = 16;
const LENFIELD: u32 = 4;
const CBIT: u32 = 9;
const FIXED_LH3: [i32; 9] = [2, 0x01, 0x01, 0x03, 0x06, 0x0D, 0x1F, 0x4E, 0];

const TREE_NODES: usize = 2 * N1;

struct StaticTree {
    c_len: [u8; N1],
    c_table: [u16; 4096],
    pt_len: [u8; NP],
    pt_table: [u16; 256],
    left: [u16; TREE_NODES],
    right: [u16; TREE_NODES],
    blocksize: u16,
    np: usize,
}

impl StaticTree {
    const fn new() -> Self {
        Self {
            c_len: [0; N1],
            c_table: [0; 4096],
            pt_len: [0; NP],
            pt_table: [0; 256],
            left: [0; TREE_NODES],
            right: [0; TREE_NODES],
            blocksize: 0,
            np: 1 << (DICBIT - 6),
        }
    }
}

#[derive(Clone, Copy)]
enum Slot {
    Table(usize),
    Left(usize),
    Right(usize),
}

fn make_table(
    nchar: usize,
    bitlen: &[u8],
    tablebits: u32,
    table: &mut [u16],
    left: &mut [u16],
    right: &mut [u16],
) -> Result<()> {
    let mut count: [u32; 17] = [0; 17];
    for &len in &bitlen[..nchar] {
        if len as usize > 16 {
            return Err(Error::Decompression("lha: code length over 16".to_owned()));
        }
        count[len as usize] += 1;
    }
    let mut start: [u32; 18] = [0; 18];
    for len in 1..=16usize {
        start[len + 1] = start[len] + (count[len] << (16 - len as u32));
    }
    if start[17] != 1 << 16 {
        if start[17] == 0 {
            return Ok(());
        }
        return Err(Error::Decompression("lha: bad huffman table".to_owned()));
    }
    let jutbits: u32 = 16 - tablebits;
    let mut weight: [u32; 17] = [0; 17];
    for slot in start.iter_mut().take(tablebits as usize + 1).skip(1) {
        *slot >>= jutbits;
    }
    for (len, slot) in weight.iter_mut().enumerate() {
        if len == 0 {
            continue;
        }
        *slot = if len <= tablebits as usize {
            1 << (tablebits - len as u32)
        } else if len <= 16 {
            1 << (16 - len as u32)
        } else {
            0
        };
    }
    let fill_from: usize = (start[tablebits as usize + 1] >> jutbits) as usize;
    let table_cap: usize = 1 << tablebits;
    if fill_from != table_cap {
        for slot in table.iter_mut().take(table_cap).skip(fill_from) {
            *slot = 0;
        }
    }
    let mut avail: usize = nchar;
    let mask: u32 = 1 << (15 - tablebits);
    let read_slot = |slot: Slot, table: &[u16], left: &[u16], right: &[u16]| -> u16 {
        match slot {
            Slot::Table(idx) => table[idx],
            Slot::Left(idx) => left[idx],
            Slot::Right(idx) => right[idx],
        }
    };
    for (ch, &raw_len) in bitlen[..nchar].iter().enumerate() {
        let len: usize = raw_len as usize;
        if len == 0 {
            continue;
        }
        let nextcode: u32 = start[len] + weight[len];
        if len <= tablebits as usize {
            let lo: usize = start[len] as usize;
            let hi: usize = (nextcode as usize).min(table_cap);
            for entry in table.iter_mut().take(hi).skip(lo) {
                *entry = ch as u16;
            }
        } else {
            let code: u32 = start[len];
            let mut slot: Slot = Slot::Table((code >> jutbits) as usize);
            let mut depth: usize = len - tablebits as usize;
            let mut bit: u32 = mask;
            while depth != 0 {
                if read_slot(slot, table, left, right) == 0 {
                    right[avail] = 0;
                    left[avail] = 0;
                    match slot {
                        Slot::Table(idx) => table[idx] = avail as u16,
                        Slot::Left(idx) => left[idx] = avail as u16,
                        Slot::Right(idx) => right[idx] = avail as u16,
                    }
                    avail += 1;
                }
                let child: usize = read_slot(slot, table, left, right) as usize;
                slot = if code & bit != 0 {
                    Slot::Right(child)
                } else {
                    Slot::Left(child)
                };
                bit >>= 1;
                depth -= 1;
            }
            match slot {
                Slot::Table(idx) => table[idx] = ch as u16,
                Slot::Left(idx) => left[idx] = ch as u16,
                Slot::Right(idx) => right[idx] = ch as u16,
            }
        }
        start[len] = nextcode;
    }
    Ok(())
}

pub fn decode(method: DynMethod, src: &[u8], original_size: u64) -> Result<Vec<u8>> {
    let max_output: u64 = u64::try_from(crate::quota::MAX_ENTRY_PREALLOC).map_err(
        |_e: std::num::TryFromIntError| {
            Error::Decompression("lha: output limit conversion failed".to_owned())
        },
    )?;
    if original_size > max_output {
        return Err(Error::Decompression(format!(
            "lha: declared output exceeds {max_output}-byte limit"
        )));
    }
    let origsize: usize = usize::try_from(original_size)
        .map_err(|_e: std::num::TryFromIntError| Error::Decompression("lha: size".to_owned()))?;
    let mut reader: BitReader<'_> = BitReader::new(src);
    let mut text: Vec<u8> = vec![b' '; DICSIZ];
    let mut out: Vec<u8> = Vec::with_capacity(origsize);
    let dicsiz1: usize = DICSIZ - 1;
    let adjust: usize = 256 - THRESHOLD;
    let mut loc: usize = 0;
    let mut decode_count: u64 = 0;

    match method {
        DynMethod::Lh2 => {
            let mut tree: Box<DynTree> = Box::new(DynTree::new());
            tree.start_c();
            tree.start_p();
            while (decode_count as usize) < origsize {
                let code: usize = tree.decode_c(&mut reader);
                if code < 256 {
                    text[loc] = code as u8;
                    out.push(code as u8);
                    loc = (loc + 1) & dicsiz1;
                    decode_count += 1;
                } else {
                    let len: usize = code - adjust;
                    let off: usize = tree.decode_p_dyn(&mut reader, decode_count) + 1;
                    let mut matchpos: usize = (loc.wrapping_sub(off)) & dicsiz1;
                    decode_count += len as u64;
                    for _ in 0..len {
                        let byte: u8 = text[matchpos];
                        text[loc] = byte;
                        out.push(byte);
                        loc = (loc + 1) & dicsiz1;
                        matchpos = (matchpos + 1) & dicsiz1;
                        if out.len() >= origsize {
                            break;
                        }
                    }
                }
            }
        }
        DynMethod::Lh3 => {
            let mut tree: Box<StaticTree> = Box::new(StaticTree::new());
            while (decode_count as usize) < origsize {
                let code: usize = decode_c_st0(&mut tree, &mut reader)?;
                if code < 256 {
                    text[loc] = code as u8;
                    out.push(code as u8);
                    loc = (loc + 1) & dicsiz1;
                    decode_count += 1;
                } else {
                    let len: usize = code - adjust;
                    let off: usize = decode_p_st0(&tree, &mut reader) + 1;
                    let mut matchpos: usize = (loc.wrapping_sub(off)) & dicsiz1;
                    decode_count += len as u64;
                    for _ in 0..len {
                        let byte: u8 = text[matchpos];
                        text[loc] = byte;
                        out.push(byte);
                        loc = (loc + 1) & dicsiz1;
                        matchpos = (matchpos + 1) & dicsiz1;
                        if out.len() >= origsize {
                            break;
                        }
                    }
                }
            }
        }
    }

    out.truncate(origsize);
    if out.len() != origsize {
        return Err(Error::Decompression(format!(
            "lha: decoded {} bytes, expected {origsize}",
            out.len()
        )));
    }
    Ok(out)
}

fn ready_made(tree: &mut StaticTree) {
    let tbl: &[i32] = &FIXED_LH3;
    let mut idx: usize = 1;
    let mut len: i32 = tbl[0];
    for sym in 0..tree.np {
        while tbl[idx] == sym as i32 {
            len += 1;
            idx += 1;
        }
        tree.pt_len[sym] = len as u8;
    }
}

fn read_tree_c(tree: &mut StaticTree, reader: &mut BitReader<'_>) -> Result<()> {
    let mut sym: usize = 0;
    while sym < N1 {
        if reader.get(1) != 0 {
            tree.c_len[sym] = (reader.get(LENFIELD) + 1) as u8;
        } else {
            tree.c_len[sym] = 0;
        }
        sym += 1;
        if sym == 3 && tree.c_len[0] == 1 && tree.c_len[1] == 1 && tree.c_len[2] == 1 {
            let code: u16 = reader.get(CBIT);
            tree.c_len.fill(0);
            tree.c_table.fill(code);
            return Ok(());
        }
    }
    let StaticTree {
        c_len,
        c_table,
        left,
        right,
        ..
    } = tree;
    make_table(N1, c_len, 12, c_table, left, right)
}

fn read_tree_p(tree: &mut StaticTree, reader: &mut BitReader<'_>) {
    let mut sym: usize = 0;
    while sym < NP {
        tree.pt_len[sym] = reader.get(LENFIELD) as u8;
        sym += 1;
        if sym == 3 && tree.pt_len[0] == 1 && tree.pt_len[1] == 1 && tree.pt_len[2] == 1 {
            let code: u16 = reader.get(DICBIT - 6);
            tree.pt_len.fill(0);
            tree.pt_table.fill(code);
            return;
        }
    }
}

fn decode_c_st0(tree: &mut StaticTree, reader: &mut BitReader<'_>) -> Result<usize> {
    if tree.blocksize == 0 {
        tree.blocksize = reader.get(BUFBITS);
        if tree.blocksize == 0 {
            return Err(Error::Decompression("lha: zero block".to_owned()));
        }
        read_tree_c(tree, reader)?;
        if reader.get(1) != 0 {
            read_tree_p(tree, reader);
        } else {
            ready_made(tree);
        }
        let StaticTree {
            pt_len,
            pt_table,
            left,
            right,
            ..
        } = &mut *tree;
        make_table(NP, pt_len, 8, pt_table, left, right)?;
    }
    tree.blocksize -= 1;
    let mut sym: usize = tree.c_table[reader.peek(12) as usize] as usize;
    if sym < N1 {
        reader.fill(u32::from(tree.c_len[sym]));
    } else {
        reader.fill(12);
        let mut bits: u16 = reader.bitbuf;
        loop {
            sym = if (bits & 0x8000) != 0 {
                tree.right[sym] as usize
            } else {
                tree.left[sym] as usize
            };
            bits <<= 1;
            if sym < N1 {
                break;
            }
        }
        reader.fill(u32::from(tree.c_len[sym]).saturating_sub(12));
    }
    if sym == N1 - 1 {
        sym += usize::from(reader.get(EXTRABITS));
    }
    Ok(sym)
}

fn decode_p_st0(tree: &StaticTree, reader: &mut BitReader<'_>) -> usize {
    let mut sym: usize = tree.pt_table[reader.peek(8) as usize] as usize;
    if sym < tree.np {
        reader.fill(u32::from(tree.pt_len[sym]));
    } else {
        reader.fill(8);
        let mut bits: u16 = reader.bitbuf;
        loop {
            sym = if (bits & 0x8000) != 0 {
                tree.right[sym] as usize
            } else {
                tree.left[sym] as usize
            };
            bits <<= 1;
            if sym < tree.np {
                break;
            }
        }
        reader.fill(u32::from(tree.pt_len[sym]).saturating_sub(8));
    }
    (sym << 6) + usize::from(reader.get(6))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rejects_declared_output_above_preallocation_bound() {
        let declared: u64 = u64::MAX;
        let outcome: std::thread::Result<Result<Vec<u8>>> =
            std::panic::catch_unwind(|| decode(DynMethod::Lh3, &[0u8; 1], declared));
        let result: Result<Vec<u8>> = outcome.expect("oversized declaration must not panic");
        assert!(result.is_err());
    }

    fn lha_crc16(data: &[u8]) -> u16 {
        let mut crc: u16 = 0;
        for &byte in data {
            crc ^= u16::from(byte);
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xA001;
                } else {
                    crc >>= 1;
                }
            }
        }
        crc
    }

    fn level2_body(archive: &[u8]) -> (&[u8], u64, u16) {
        let word_len: usize = usize::from(u16::from_le_bytes([archive[0], archive[1]]));
        let original_size: u64 = u64::from(u32::from_le_bytes([
            archive[11],
            archive[12],
            archive[13],
            archive[14],
        ]));
        let compressed_size: usize =
            u32::from_le_bytes([archive[7], archive[8], archive[9], archive[10]]) as usize;
        let file_crc: u16 = u16::from_le_bytes([archive[21], archive[22]]);
        let body: &[u8] = &archive[word_len..word_len + compressed_size];
        (body, original_size, file_crc)
    }

    #[test]
    fn lh2_real_archive_matches_stored_crc() {
        let archive: &[u8] = include_bytes!("../../tests/fixtures/lzh/lh2.lzh");
        let (body, original_size, file_crc): (&[u8], u64, u16) = level2_body(archive);
        let decoded: Vec<u8> = decode(DynMethod::Lh2, body, original_size).expect("lh2 decode");
        assert_eq!(decoded.len() as u64, original_size);
        assert_eq!(
            lha_crc16(&decoded),
            file_crc,
            "lh2 output crc16 must match the archive's stored crc"
        );
    }

    #[test]
    fn lh3_real_archive_matches_stored_crc() {
        let archive: &[u8] = include_bytes!("../../tests/fixtures/lzh/lh3.lzh");
        let (body, original_size, file_crc): (&[u8], u64, u16) = level2_body(archive);
        let decoded: Vec<u8> = decode(DynMethod::Lh3, body, original_size).expect("lh3 decode");
        assert_eq!(decoded.len() as u64, original_size);
        assert_eq!(
            lha_crc16(&decoded),
            file_crc,
            "lh3 output crc16 must match the archive's stored crc"
        );
    }

    #[test]
    fn lh2_and_lh3_recover_identical_content() {
        let lh2: &[u8] = include_bytes!("../../tests/fixtures/lzh/lh2.lzh");
        let lh3: &[u8] = include_bytes!("../../tests/fixtures/lzh/lh3.lzh");
        let (b2, s2, _): (&[u8], u64, u16) = level2_body(lh2);
        let (b3, s3, _): (&[u8], u64, u16) = level2_body(lh3);
        let d2: Vec<u8> = decode(DynMethod::Lh2, b2, s2).expect("lh2");
        let d3: Vec<u8> = decode(DynMethod::Lh3, b3, s3).expect("lh3");
        assert_eq!(d2, d3, "lh2 and lh3 archive the same source file");
    }

    #[test]
    fn short_codelength_in_walked_branch_does_not_underflow() {
        let body: [u8; 78] = [
            178, 163, 132, 33, 177, 54, 160, 43, 183, 210, 233, 188, 189, 204, 203, 198, 57, 35,
            153, 112, 72, 56, 24, 178, 235, 100, 194, 247, 104, 246, 87, 33, 11, 159, 114, 78, 54,
            76, 112, 50, 16, 144, 203, 132, 21, 23, 45, 185, 180, 143, 76, 198, 207, 66, 80, 80,
            36, 108, 48, 198, 251, 176, 97, 245, 22, 42, 156, 43, 231, 188, 83, 185, 36, 126, 62,
            30, 248, 25,
        ];
        let _ = decode(DynMethod::Lh3, &body, 65_536);
    }
}
