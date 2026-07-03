use crate::error::{Error, Result};

const MEMSHIFT: u32 = 23;
const MEM: usize = 1 << MEMSHIFT;
const NMODEL: usize = 11;
const NINPUT: usize = 48;
const NWEIGHT: usize = 256 + 256 + 16 + 128;
const MAXLEN: u32 = 2047;
const APMSIZE: usize = 8192;

const MODELMEM_MASK: usize = ((MEM / 4) - 1) & !1;
const MATCH_SLOTS: usize = MEM / 16;

const RENORM_THRESHOLD: u32 = 0x0100_0000;
const PROB_BITS: u32 = 12;

const ZERO_RUN: usize = 8192;
const BITCOUNTER_WRAP: u32 = 1 << 16;

const OUTPUT_CAP: usize = 64 * 1024 * 1024;

const SQUASH_TAB: [i32; 33] = [
    1, 2, 4, 6, 10, 17, 27, 45, 74, 120, 194, 311, 488, 747, 1102, 1546, 2048, 2550, 2994, 3349,
    3608, 3785, 3902, 3976, 4022, 4051, 4069, 4079, 4086, 4090, 4092, 4094, 4095,
];

const MASKS: [u8; NMODEL] = [
    0x1f, 0x27, 0x88, 0x07, 0x0a, 0x09, 0x05, 0x03, 0x04, 0x02, 0x01,
];
const BITM: [u8; NMODEL] = [
    0xff, 0xff, 0xff, 0xe0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

fn squash(x: i32) -> i32 {
    if x < -2047 {
        return 0;
    }
    if x > 2047 {
        return 4095;
    }
    let idx: usize = ((x >> 7) + 16) as usize;
    let w: i32 = x & 127;
    let delta: i32 = (SQUASH_TAB[idx + 1] - SQUASH_TAB[idx]) & 0xffff;
    let interp: i32 = (w * delta + 64) >> 7;
    (interp + SQUASH_TAB[idx]) & 0xffff
}

fn build_run_table() -> [u32; 256] {
    let mut table: [u32; 256] = [0u32; 256];
    let mut acc: u32 = 14_155_776;
    let mut c: u32 = 1;
    while c < 256 {
        acc = acc.wrapping_add(774_541_002 / (2 * c + 1));
        table[c as usize] = acc >> 21;
        c += 1;
    }
    table
}

fn build_state_tables(run_table: &[u32; 256]) -> (Vec<u8>, [u8; 512], [u32; 256]) {
    let mut state_code: [u8; 512] = [0u8; 512];
    let mut state_next: [u8; 512] = [0u8; 512];

    let mut eax: u32 = 0;
    let mut ebx: u32 = 0;
    let mut ecx: u32 = 4;
    let mut esi: usize = 0;

    loop {
        ebx ^= 1;
        let hi_src: usize = (ebx & 0x1ff) as usize;
        eax = (eax & 0xffff_00ff) | (u32::from(state_code[hi_src]) << 8);
        let opp: u32 = (eax >> 8) & 0xff;
        if opp > 2 {
            eax = run_table[(opp - 1) as usize].wrapping_shl(2);
            let new_hi: u32 = ((eax >> 8) & 0xff).wrapping_sub(1) & 0xff;
            eax = (eax & 0xffff_00ff) | (new_hi << 8);
        }
        ebx ^= 1;
        let lo_src: usize = (ebx & 0x1ff) as usize;
        eax = (eax & 0xffff_ff00) | u32::from(state_code[lo_src]);
        eax = eax.wrapping_add(1);
        if eax & 0xff > 40 {
            eax = (eax & 0xffff_ff00) | 0x28;
        }
        if ebx & 1 != 0 {
            let al: u32 = eax & 0xff;
            let ah: u32 = (eax >> 8) & 0xff;
            eax = (eax & 0xffff_0000) | (al << 8) | ah;
        }
        let ax: u16 = (eax & 0xffff) as u16;

        let edx: u32 = ecx;
        let mut k: usize = 0;
        let mut rem: u32 = ecx;
        let mut found: bool = false;
        while rem != 0 {
            let word: u16 = (u16::from(state_code[2 * k + 1]) << 8) | u16::from(state_code[2 * k]);
            rem -= 1;
            k += 1;
            if word == ax {
                found = true;
                break;
            }
        }
        let (idx_word, new_count, ecx_after): (usize, u32, u32) = if found {
            (k, edx, rem)
        } else {
            (k + 1, edx.wrapping_add(1), rem.wrapping_sub(1))
        };
        let cl_index: u32 =
            (!ecx_after).wrapping_add(if found { edx } else { edx.wrapping_add(1) });
        let write_word: usize = idx_word - 1;
        state_code[2 * write_word] = (ax & 0xff) as u8;
        state_code[2 * write_word + 1] = (ax >> 8) as u8;
        state_next[esi] = (cl_index & 0xff) as u8;
        esi += 1;
        ecx = new_count;
        ebx = ebx.wrapping_add(1);
        if (ebx >> 8) & 0xff == 2 {
            break;
        }
    }

    let mut state_map: [u32; 256] = [0u32; 256];
    let mut s: usize = 0;
    while s < 256 {
        let n0: u32 = u32::from(state_code[2 * s]);
        let n1: u32 = u32::from(state_code[2 * s + 1]);
        let numer: u32 = n0 + 1;
        let denom: u32 = (n1 + 1) + numer;
        state_map[s] = (numer << 16) / denom;
        s += 1;
    }

    let mut and_mask: Vec<u8> = vec![0u8; 512];
    let mut i: usize = 0;
    while i < 512 {
        let raw: u8 = state_code[i];
        and_mask[i] = if raw == 0 { 0xff } else { 0x00 };
        i += 1;
    }

    (and_mask, state_next, state_map)
}

fn build_stretch_table() -> Vec<i32> {
    let mut stretch: Vec<i32> = vec![0i32; 4096];
    let mut prev: i32 = -1;
    let mut cursor: usize = 0;
    let mut i: i32 = -2047;
    while i <= 2048 {
        let s: i32 = squash(i);
        let mut count: i32 = s - prev;
        while count > 0 {
            if cursor < 4096 {
                stretch[cursor] = i;
            }
            cursor += 1;
            count -= 1;
        }
        prev = s;
        i += 1;
    }
    stretch
}

#[derive(Clone, Copy, Default)]
struct ContextModel {
    cpr: usize,
    cps: usize,
    ctx: u32,
    st: u32,
}

struct Model {
    run_table: [u32; 256],
    state_code: Vec<u8>,
    state_next: [u8; 512],
    state_map: [u32; 256],
    stretch: Vec<i32>,
    hash_mem: Vec<u8>,
    matches: Vec<u32>,
    cm: [ContextModel; NMODEL],
    wx: Vec<i16>,
    wx2: [i16; 8],
    tx: [i16; NINPUT],
    tx2: [i16; 4],
    apm: Vec<i32>,
    c0: u32,
    c0s: u32,
    bpos: u32,
    bit: u32,
    bitscaled: i32,
    matchp: usize,
    matchl: u32,
    matchw: u32,
    lentemp: u32,
    ctx_sel: [u32; 3],
    pr: [i32; 4],
    out_prob: i32,
    apm_i: i32,
    dst_pos: usize,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("c0", &self.c0)
            .field("bpos", &self.bpos)
            .field("matchl", &self.matchl)
            .field("out_prob", &self.out_prob)
            .field("dst_pos", &self.dst_pos)
            .finish_non_exhaustive()
    }
}

impl Model {
    fn new() -> Self {
        let run_table: [u32; 256] = build_run_table();
        let (and_mask, state_next, state_map): (Vec<u8>, [u8; 512], [u32; 256]) =
            build_state_tables(&run_table);
        let stretch: Vec<i32> = build_stretch_table();
        let mut model: Self = Self {
            run_table,
            state_code: and_mask,
            state_next,
            state_map,
            stretch,
            hash_mem: vec![0u8; MEM],
            matches: vec![0u32; MATCH_SLOTS],
            cm: [ContextModel::default(); NMODEL],
            wx: vec![0i16; NINPUT * NWEIGHT],
            wx2: [0i16; 8],
            tx: [0i16; NINPUT],
            tx2: [0i16; 4],
            apm: vec![0i32; APMSIZE * 33],
            c0: 1,
            c0s: 0,
            bpos: 8,
            bit: 0,
            bitscaled: 0,
            matchp: 0,
            matchl: 0,
            matchw: 0,
            lentemp: 0,
            ctx_sel: [0u32; 3],
            pr: [2048i32; 4],
            out_prob: 2048,
            apm_i: 0,
            dst_pos: 0,
        };
        model.init_context_models();
        model.init_apm();
        model
    }

    fn context_hash(&mut self, key: u32) -> usize {
        let tag: u8 = (key >> 24) as u8;
        let base: usize = ((key as usize) & MODELMEM_MASK) * 4;
        if self.hash_mem[base] == tag {
            return base + 1;
        }
        let way1: usize = base + 4;
        if self.hash_mem[way1] == tag {
            return way1 + 1;
        }
        let evict: usize = if self.hash_mem[way1 + 1] <= self.hash_mem[base + 1] {
            way1
        } else {
            base
        };
        self.hash_mem[evict] = tag;
        self.hash_mem[evict + 1] = 0;
        self.hash_mem[evict + 2] = 0;
        self.hash_mem[evict + 3] = 0;
        evict + 1
    }

    fn init_context_models(&mut self) {
        let mut i: usize = 0;
        while i < NMODEL {
            let cpr: usize = self.context_hash(1);
            self.cm[i].cpr = cpr;
            let cps: usize = self.context_hash(0);
            self.cm[i].cps = cps;
            i += 1;
        }
    }

    fn init_apm(&mut self) {
        let mut block: [i32; 33] = [0i32; 33];
        let mut x: i32 = -16;
        let mut j: usize = 0;
        while x <= 16 {
            block[j] = squash(x << 7) << 4;
            j += 1;
            x += 1;
        }
        let mut b: usize = 0;
        while b < APMSIZE {
            let dst: usize = b * 33;
            self.apm[dst..dst + 33].copy_from_slice(&block);
            b += 1;
        }
    }

    fn train(&mut self, err: i32, w_base: usize, lanes: usize) {
        let err16: i32 = i32::from(err as i16);
        let mut i: usize = 0;
        while i < lanes {
            let t: i32 = i32::from(self.tx[i]);
            let two_t: i32 = sat16(t.wrapping_add(t));
            let prod: i32 = (two_t * err16) >> 16;
            let prod16: i32 = sat16(prod);
            let rounded: i32 = sat16(prod16 + 1) >> 1;
            let w: i32 = i32::from(self.wx[w_base + i]);
            self.wx[w_base + i] = sat16(w + rounded) as i16;
            i += 1;
        }
    }

    fn train_final(&mut self, err: i32) {
        let err16: i32 = i32::from(err as i16);
        let mut i: usize = 0;
        while i < 4 {
            let t: i32 = i32::from(self.tx2[i]);
            let two_t: i32 = sat16(t.wrapping_add(t));
            let prod: i32 = (two_t * err16) >> 16;
            let prod16: i32 = sat16(prod);
            let rounded: i32 = sat16(prod16 + 1) >> 1;
            let w: i32 = i32::from(self.wx2[i]);
            self.wx2[i] = sat16(w + rounded) as i16;
            i += 1;
        }
    }

    fn update_mixers(&mut self) {
        let mut k: usize = 0;
        while k < 3 {
            let err: i32 = ((self.bit as i32) << 12)
                .wrapping_sub(self.pr[k])
                .wrapping_mul(7);
            let sel: u32 = self.ctx_sel[k];
            let w_base: usize = (sel as usize) * NINPUT;
            self.train(err, w_base, NINPUT);
            k += 1;
        }
        let err3: i32 = ((self.bit as i32) << 12)
            .wrapping_sub(self.pr[3])
            .wrapping_mul(7);
        self.train_final(err3);
    }

    fn read_prev(&self, back: usize, buffer: &[u8]) -> u8 {
        let pos: usize = self.dst_pos;
        if pos >= back {
            let idx: usize = pos - back;
            if idx < buffer.len() {
                return buffer[idx];
            }
        }
        0
    }

    fn update_context_models(&mut self, buffer: &[u8]) {
        self.bpos = 8;
        self.c0 = 1;
        let mut eax: u32 = 0;
        let mut m: usize = 0;
        while m < NMODEL {
            eax &= !1u32;
            self.cm[m].ctx = eax;

            let cpr: usize = self.cm[m].cpr;
            let prev_byte: u8 = self.read_prev(1, buffer);
            if prev_byte != self.hash_mem[cpr + 1] {
                self.hash_mem[cpr] = 0;
                self.hash_mem[cpr + 1] = prev_byte;
            }
            self.hash_mem[cpr] = self.hash_mem[cpr].wrapping_add(1);
            eax = eax.wrapping_add(1);
            let new_cpr: usize = self.context_hash(eax);
            self.cm[m].cpr = new_cpr;

            let countdown: u32 = (NMODEL - m) as u32;
            let mut hash: u32 = 0x811c_9dc5u32.wrapping_mul(countdown + 1);
            let mask_index: usize = NMODEL - m - 1;
            let mask: u8 = MASKS[mask_index];
            let bit_and: u8 = BITM[mask_index];
            let mut bl: u8 = mask;
            let mut offset: usize = 0;
            loop {
                offset += 1;
                let carry: bool = bl & 1 != 0;
                bl >>= 1;
                if carry {
                    let byte: u8 = self.read_prev(offset, buffer) & bit_and;
                    hash ^= u32::from(byte);
                    hash = hash.wrapping_mul(0x0100_0193);
                } else if bl == 0 {
                    break;
                }
            }
            eax = hash;
            m += 1;
        }

        let slot: usize = (eax as usize) & (MATCH_SLOTS - 1);
        let prior: u32 = self.matches[slot];
        self.matches[slot] = self.dst_pos as u32;
        let candidate: usize = prior as usize;

        let len: u32 = if self.matchl != 0 {
            self.matchp += 1;
            self.matchl + 1
        } else if candidate == 0 {
            0
        } else {
            self.matchp = candidate;
            self.lentemp = candidate as u32;
            let mut counted: u32 = 0;
            let mut a: usize = candidate;
            let mut b: usize = self.dst_pos;
            while a != 0 {
                let prev_a: usize = a - 1;
                let prev_b: usize = b.wrapping_sub(1);
                if byte_at(prev_a, buffer) != byte_at(prev_b, buffer) {
                    break;
                }
                counted += 1;
                a = prev_a;
                b = prev_b;
            }
            counted
        };

        let clamped_len: u32 = len.min(MAXLEN);
        self.matchl = clamped_len;
        let capped: u32 = clamped_len.min(32);
        self.matchw = capped << 6;
    }

    fn build_inputs(&mut self, buffer: &[u8]) {
        self.c0s = self.c0 << 3;
        self.tx = [0i16; NINPUT];
        let mut idx: usize = 0;
        self.tx[idx] = 127;
        idx += 1;

        let match_val: i32 = self.match_input(buffer);
        self.tx[idx] = match_val as i16;
        idx += 1;

        if self.matchl > 400 {
            self.ctx_sel[0] = 512 + 14;
            self.mix(buffer);
            return;
        }

        let mut ctx2_count: u32 = 2;
        let mut m: usize = 0;
        while m < NMODEL {
            let run_val: i32 = self.run_input(m);
            self.tx[idx] = run_val as i16;
            idx += 1;

            self.nonstationary_update(m);

            let st: u32 = self.cm[m].st;
            let bias: i32 = self.bitscaled;
            let map_idx: usize = st as usize;
            let cur: i32 = self.state_map[map_idx] as i32;
            let delta: i32 = (bias.wrapping_sub(cur)) >> 8;
            self.state_map[map_idx] = (cur.wrapping_add(delta)) as u32;

            let cps: usize = self.cm[m].cps;
            let new_st: u32 = u32::from(self.hash_mem[cps]);
            self.cm[m].st = new_st;
            let stretched_src: usize = (self.state_map[new_st as usize] >> 4) as usize;
            let stretch_val: i32 = self.stretch[stretched_src & 0xfff] >> 2;
            self.tx[idx] = stretch_val as i16;
            idx += 1;

            let eax: u32 = self.state_map[new_st as usize] >> 4;
            let edx: u32 = eax;
            let dl_not: u8 = !(edx as u8);
            let stosw1: i32 = (eax as i32).wrapping_sub(i32::from(dl_not));
            self.tx[idx] = stosw1 as i16;
            idx += 1;

            let al_mask: u8 = self.state_code[(new_st as usize) * 2];
            let dl_mask: u8 = self.state_code[(new_st as usize) * 2 + 1];
            let al_val: u8 = (eax as u8) & al_mask;
            let dl_val: u8 = dl_not & dl_mask;
            let stosw2: i32 = i32::from(al_val as i8).wrapping_sub(i32::from(dl_val as i8));
            self.tx[idx] = stosw2 as i16;
            idx += 1;

            if new_st >= 1 {
                ctx2_count = ctx2_count.wrapping_add(1);
            }
            m += 1;
        }

        self.ctx_sel[2] = ctx2_count;
        let prev_byte: u8 = self.read_prev(1, buffer);
        self.ctx_sel[0] = u32::from(prev_byte);
        self.ctx_sel[1] = 0x100 | (self.c0 & 0xff);

        let tmp: i32 = (self.matchl as i32).wrapping_sub(1).clamp(0, 0xff);
        let run_add: u32 = self.run_table[tmp as usize] >> 3;
        self.ctx_sel[2] = self.ctx_sel[2].wrapping_add(run_add);

        self.mix(buffer);
    }

    fn match_input(&mut self, buffer: &[u8]) -> i32 {
        if self.matchl == 0 {
            return 0;
        }
        let predicted: u32 = u32::from(byte_at(self.matchp, buffer));
        let marked: u32 = predicted | 0x100;
        let bpos: u32 = self.bpos;
        let shifted: u32 = marked >> bpos;
        let carry: u32 = if bpos == 0 {
            0
        } else {
            (marked >> (bpos - 1)) & 1
        };
        if shifted != self.c0 {
            self.matchl = 0;
            return 0;
        }
        let neg: u32 = 0u32.wrapping_sub(carry);
        let val: u32 = (self.matchw ^ neg).wrapping_sub(neg);
        val as i32
    }

    fn run_input(&self, m: usize) -> i32 {
        let cpr: usize = self.cm[m].cpr;
        let run_len: u8 = self.hash_mem[cpr];
        let marked_last: u32 = u32::from(self.hash_mem[cpr + 1]) | 0x100;
        let bpos: u32 = self.bpos;
        let run_val_raw: u32 = self.run_table[run_len as usize];
        let edx: u32 = marked_last >> bpos;
        let carry: u32 = if bpos == 0 {
            0
        } else {
            (marked_last >> (bpos - 1)) & 1
        };
        let neg: u32 = 0u32.wrapping_sub(carry);
        let signed_run: u32 = (run_val_raw ^ neg).wrapping_sub(neg);
        if edx == self.c0 { signed_run as i32 } else { 0 }
    }

    fn nonstationary_update(&mut self, m: usize) {
        let cps: usize = self.cm[m].cps;
        let state: u8 = self.hash_mem[cps];
        let lookup: usize = (usize::from(state) * 2) + (self.bit as usize);
        let next: u8 = self.state_next[lookup & 0x1ff];
        self.hash_mem[cps] = next;

        let mixed: u32 = self.cm[m].ctx ^ self.c0s;
        let new_cps: usize = self.context_hash(mixed);
        self.cm[m].cps = new_cps;
    }

    fn mix(&mut self, buffer: &[u8]) {
        let mut k: i32 = 2;
        while k >= 0 {
            let sel: u32 = self.ctx_sel[k as usize];
            let w_base: usize = (sel as usize) * NINPUT;
            let mut acc: i64 = 0;
            let mut g: usize = 0;
            while g < NINPUT / 4 {
                let i0: usize = g * 4;
                let t0: i32 = i32::from(self.tx[i0]);
                let t1: i32 = i32::from(self.tx[i0 + 1]);
                let t2: i32 = i32::from(self.tx[i0 + 2]);
                let t3: i32 = i32::from(self.tx[i0 + 3]);
                let w0: i32 = i32::from(self.wx[w_base + i0]);
                let w1: i32 = i32::from(self.wx[w_base + i0 + 1]);
                let w2: i32 = i32::from(self.wx[w_base + i0 + 2]);
                let w3: i32 = i32::from(self.wx[w_base + i0 + 3]);
                let lane0: i32 = (t0.wrapping_mul(w0).wrapping_add(t1.wrapping_mul(w1))) >> 8;
                let lane1: i32 = (t2.wrapping_mul(w2).wrapping_add(t3.wrapping_mul(w3))) >> 8;
                acc = acc
                    .wrapping_add(i64::from(lane0))
                    .wrapping_add(i64::from(lane1));
                g += 1;
            }
            let folded: i32 = (acc & 0xffff_ffff) as i32;
            let mixed: i32 = folded >> 3;
            self.tx2[k as usize] = mixed as i16;
            self.pr[k as usize] = squash(mixed);
            k -= 1;
        }

        let mut acc2: i32 = 0;
        let mut i: usize = 0;
        while i < 3 {
            let w: i32 = i32::from(self.wx2[i]);
            let t: i32 = i32::from(self.tx2[i]);
            acc2 = acc2.wrapping_add(w.wrapping_mul(t));
            i += 1;
        }
        let final_mix: i32 = acc2 >> 16;
        self.pr[3] = squash(final_mix);

        self.apm_stage(buffer);
    }

    fn apm_index(&self, signed: i32) -> usize {
        let idx: i32 = 16i32.wrapping_add(signed);
        (idx as usize).min(self.apm.len() - 2)
    }

    fn apm_stage(&mut self, buffer: &[u8]) {
        let eax_in: i32 = self.pr[3];
        let g: i32 = (0i32.wrapping_sub(self.bit as i32)) & 0x100fe;
        let base: usize = self.apm_index(self.apm_i);
        let cur0: i32 = self.apm[base];
        self.apm[base] = cur0.wrapping_add((g.wrapping_sub(cur0)) >> 8);
        let cur1: i32 = self.apm[base + 1];
        self.apm[base + 1] = cur1.wrapping_add((g.wrapping_sub(cur1)) >> 8);

        let prev_byte: u32 = u32::from(self.read_prev(1, buffer));
        let mut bx: u32 = (prev_byte << 4).wrapping_add(prev_byte);
        bx = bx.wrapping_add(self.c0) & (APMSIZE as u32 - 1);
        bx = bx.wrapping_mul(33);

        let stretch_val: i32 = self.stretch[(eax_in as usize) & 0xfff];
        let offset: i32 = stretch_val >> 7;
        self.apm_i = (bx as i32).wrapping_add(offset);

        let w: i32 = stretch_val & 127;
        let lo_idx: usize = self.apm_index(self.apm_i);
        let lo: i32 = self.apm[lo_idx];
        let hi: i32 = self.apm[lo_idx + 1];
        let diff: i32 = hi.wrapping_sub(lo);
        let combined: i32 = (lo << 7).wrapping_add(diff.wrapping_mul(w));
        self.out_prob = combined >> 11;
    }

    fn coded_prob(&self) -> u32 {
        let p: i32 = self.out_prob;
        let ah: i32 = (p >> 8) & 0xff;
        let adj: i32 = i32::from(ah < 8);
        (p + adj) as u32
    }

    fn after_bit(&mut self, bit: u32, buffer: &[u8]) {
        self.bit = bit;
        self.bitscaled = ((bit as i32) << 16).wrapping_add(128);
        self.update_mixers();
        self.c0 = (self.c0 << 1).wrapping_add(bit);
        self.bpos = self.bpos.wrapping_sub(1);
        if self.bpos == 0 {
            self.update_context_models(buffer);
        }
        self.build_inputs(buffer);
    }
}

fn sat16(v: i32) -> i32 {
    v.clamp(-32768, 32767)
}

fn byte_at(pos: usize, buffer: &[u8]) -> u8 {
    buffer.get(pos).copied().unwrap_or(0)
}

struct RangeDecoder<'a> {
    input: &'a [u8],
    pos: usize,
    code: u32,
    range: u32,
}

impl std::fmt::Debug for RangeDecoder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RangeDecoder")
            .field("pos", &self.pos)
            .field("code", &self.code)
            .field("range", &self.range)
            .finish()
    }
}

impl<'a> RangeDecoder<'a> {
    fn new(input: &'a [u8]) -> Result<Self> {
        if input.len() < 4 {
            return Err(Error::Truncated {
                needed: 4,
                had: input.len(),
            });
        }
        let mut code: u32 = 0;
        let mut pos: usize = 0;
        while pos < 4 {
            code = (code << 8) | u32::from(input[pos]);
            pos += 1;
        }
        Ok(Self {
            input,
            pos,
            code,
            range: 0xffff_ffff,
        })
    }

    fn next_byte(&mut self) -> Result<u8> {
        if self.pos >= self.input.len() {
            return Err(Error::Truncated {
                needed: self.pos + 1,
                had: self.input.len(),
            });
        }
        let b: u8 = self.input[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn decode_bit(&mut self, prob: u32) -> Result<u32> {
        let bound: u32 = ((u64::from(self.range) * u64::from(prob)) >> PROB_BITS) as u32;
        let bit: u32 = if self.code < bound {
            self.range = bound;
            1
        } else {
            self.code = self.code.wrapping_sub(bound);
            self.range = self.range.wrapping_sub(bound);
            0
        };
        while self.range < RENORM_THRESHOLD {
            let b: u8 = self.next_byte()?;
            self.code = (self.code << 8) | u32::from(b);
            self.range <<= 8;
        }
        Ok(bit)
    }
}

pub fn rangecoder_depack(input: &[u8], out_size: usize) -> Result<Vec<u8>> {
    if out_size > OUTPUT_CAP {
        return Err(Error::SignatureDb(format!(
            "kkrunchy_k7 declared output {out_size} exceeds {OUTPUT_CAP}-byte cap"
        )));
    }
    let mut decoder: RangeDecoder<'_> = RangeDecoder::new(input)?;
    let mut model: Model = Model::new();
    let mut out: Vec<u8> = Vec::with_capacity(out_size.min(OUTPUT_CAP));
    let mut zero_prob: u32 = 1;
    let mut bitcounter: u32 = 0;
    let mut current: u8 = 1;

    let max_bits: u64 = (out_size as u64) * 8 + (out_size as u64 / ZERO_RUN as u64 + 2) + 16;
    let mut budget: u64 = max_bits.saturating_mul(4).saturating_add(1024);

    while out.len() < out_size {
        if bitcounter == 0 {
            if budget == 0 {
                return Err(Error::SignatureDb(
                    "kkrunchy_k7 decode step budget exhausted (zero-tag loop)".to_owned(),
                ));
            }
            budget -= 1;
            let is_zero: u32 = decoder.decode_bit(zero_prob)?;
            zero_prob = (zero_prob + if is_zero != 0 { 4096 } else { 1 }) >> 1;
            if is_zero != 0 {
                let remaining: usize = out_size - out.len();
                let run: usize = remaining.min(ZERO_RUN);
                out.resize(out.len() + run, 0);
                model.dst_pos = out.len();
                continue;
            }
        }

        if budget == 0 {
            return Err(Error::SignatureDb(
                "kkrunchy_k7 decode step budget exhausted".to_owned(),
            ));
        }
        budget -= 1;

        let prob: u32 = model.coded_prob();
        let bit: u32 = decoder.decode_bit(prob)?;
        bitcounter = bitcounter.wrapping_add(1) & (BITCOUNTER_WRAP - 1);

        let carry: bool = current & 0x80 != 0;
        current = (current << 1) | (bit as u8);
        if carry {
            out.push(current);
            model.dst_pos = out.len();
            current = 1;
            if out.len() >= out_size {
                break;
            }
        }

        model.after_bit(bit, &out);
    }

    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    struct RangeEncoder {
        out: Vec<u8>,
        low: u64,
        range: u32,
        cache: u8,
        ff_num: u64,
        first: bool,
    }

    impl RangeEncoder {
        fn new() -> Self {
            Self {
                out: Vec::new(),
                low: 0,
                range: 0xffff_ffff,
                cache: 0,
                ff_num: 0,
                first: true,
            }
        }

        fn shift_low(&mut self) {
            let carry: u32 = (self.low >> 32) as u32;
            if self.low < 0xff00_0000 || carry == 1 {
                if self.first {
                    self.first = false;
                } else {
                    self.out.push(self.cache.wrapping_add(carry as u8));
                }
                while self.ff_num != 0 {
                    self.out.push(0xffu8.wrapping_add(carry as u8));
                    self.ff_num -= 1;
                }
                self.cache = ((self.low >> 24) & 0xff) as u8;
            } else {
                self.ff_num += 1;
            }
            self.low = (self.low << 8) & 0xffff_ffff;
        }

        fn code_bit(&mut self, prob: u32, bit: u32) {
            let bound: u32 = ((u64::from(self.range) * u64::from(prob)) >> PROB_BITS) as u32;
            if bit != 0 {
                self.range = bound;
            } else {
                self.low += u64::from(bound);
                self.range = self.range.wrapping_sub(bound);
            }
            while self.range < RENORM_THRESHOLD {
                self.range <<= 8;
                self.shift_low();
            }
        }

        fn finish(&mut self) {
            for _ in 0..5 {
                self.shift_low();
            }
        }
    }

    fn encode(input: &[u8]) -> Vec<u8> {
        let mut enc: RangeEncoder = RangeEncoder::new();
        let mut model: Model = Model::new();
        let mut zero_prob: u32 = 1;
        let mut pos: usize = 0;
        let total: usize = input.len();
        while pos < total {
            if pos & (ZERO_RUN - 1) == 0 {
                let mut is_zero: u32 = u32::from(total - pos > ZERO_RUN);
                if is_zero != 0 {
                    let mut i: usize = 0;
                    while i < ZERO_RUN {
                        if input[pos + i] != 0 {
                            is_zero = 0;
                            break;
                        }
                        i += 1;
                    }
                }
                enc.code_bit(zero_prob, is_zero);
                zero_prob = (zero_prob + if is_zero != 0 { 4096 } else { 1 }) >> 1;
                if is_zero != 0 {
                    model.dst_pos = pos + ZERO_RUN;
                    pos += ZERO_RUN;
                    continue;
                }
            }
            let byte: u8 = input[pos];
            let mut i: usize = 0;
            while i < 8 {
                let bit: u32 = u32::from((byte >> (7 - i)) & 1);
                let prob: u32 = model.coded_prob();
                enc.code_bit(prob, bit);
                if i == 7 {
                    model.dst_pos = pos + 1;
                }
                model.after_bit(bit, &input[..=pos]);
                i += 1;
            }
            pos += 1;
        }
        enc.finish();
        enc.out
    }

    fn lcg_bytes(seed: u32, len: usize) -> Vec<u8> {
        let mut state: u32 = seed;
        let mut out: Vec<u8> = Vec::with_capacity(len);
        let mut i: usize = 0;
        while i < len {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            out.push((state >> 24) as u8);
            i += 1;
        }
        out
    }

    fn round_trip(input: &[u8]) {
        let packed: Vec<u8> = encode(input);
        let depacked: Vec<u8> = rangecoder_depack(&packed, input.len()).expect("depack");
        assert_eq!(
            depacked,
            input,
            "self-consistency round-trip failed (len={})",
            input.len()
        );
    }

    #[test]
    fn squash_reference_anchors() {
        assert_eq!(squash(-2048), 0);
        assert_eq!(squash(-2047), 1);
        assert_eq!(squash(0), 2048);
        assert_eq!(squash(2047), 4095);
        assert_eq!(squash(2048), 4095);
        assert_eq!(squash(-128), 1546);
        assert_eq!(squash(128), 2550);
        assert_eq!(squash(256), 2994);
    }

    #[test]
    fn run_table_reference_values() {
        let table: [u32; 256] = build_run_table();
        assert_eq!(table[0], 0);
        assert_eq!(table[1], 129);
        assert_eq!(table[2], 203);
        assert_eq!(table[3], 256);
        assert_eq!(table[255], 1024);
    }

    #[test]
    fn run_table_matches_independent_integration() {
        let table: [u32; 256] = build_run_table();
        let mut acc: u64 = 14_155_776;
        let mut c: u64 = 1;
        while c < 256 {
            acc += 774_541_002u64 / (2 * c + 1);
            let expected: u32 = (acc >> 21) as u32;
            assert_eq!(table[c as usize], expected, "run_table[{c}] mismatch");
            c += 1;
        }
    }

    #[test]
    fn state_table_converges_to_256_states() {
        let run_table: [u32; 256] = build_run_table();
        let (and_mask, state_next, state_map): (Vec<u8>, [u8; 512], [u32; 256]) =
            build_state_tables(&run_table);
        assert_eq!(and_mask.len(), 512);
        assert_eq!(state_next.len(), 512);
        assert_eq!(state_map.len(), 256);
        let max_next: u32 = state_next.iter().map(|&b: &u8| u32::from(b)).max().unwrap();
        assert_eq!(
            max_next, 255,
            "state machine must reference all 256 states (convergence to 0x100)"
        );
        assert_eq!(
            &state_next[0..10],
            &[5, 6, 4, 5, 4, 5, 4, 5, 7, 8],
            "stateNext transition anchors must match the published reference build"
        );
    }

    #[test]
    fn state_map_reference_values() {
        let run_table: [u32; 256] = build_run_table();
        let (_and_mask, _state_next, state_map): (Vec<u8>, [u8; 512], [u32; 256]) =
            build_state_tables(&run_table);
        assert_eq!(state_map[0], 0x8000);
        assert_eq!(state_map[4], 43690);
        assert_eq!(state_map[5], 21845);
        assert_eq!(state_map[6], 49152);
    }

    #[test]
    fn state_code_andmask_first_states() {
        let run_table: [u32; 256] = build_run_table();
        let (and_mask, _state_next, _state_map): (Vec<u8>, [u8; 512], [u32; 256]) =
            build_state_tables(&run_table);
        assert_eq!(
            &and_mask[0..8],
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
        assert_eq!(and_mask[8], 0x00);
        assert_eq!(and_mask[9], 0xff);
    }

    #[test]
    fn stretch_is_monotone_and_inverts_squash() {
        let stretch: Vec<i32> = build_stretch_table();
        assert_eq!(stretch.len(), 4096);
        let mut k: usize = 0;
        while k < 4095 {
            assert!(
                stretch[k] <= stretch[k + 1],
                "stretch not monotone at {k}: {} > {}",
                stretch[k],
                stretch[k + 1]
            );
            k += 1;
        }
        assert_eq!(stretch[squash(0) as usize], 0);
        assert_eq!(stretch[squash(500) as usize], 500);
        let mut x: i32 = -2000;
        while x <= 2000 {
            let back: i32 = stretch[squash(x) as usize];
            assert!((back - x).abs() <= 256, "stretch(squash({x}))={back}");
            x += 17;
        }
    }

    #[test]
    fn round_trip_empty() {
        round_trip(&[]);
    }

    #[test]
    fn round_trip_single_byte() {
        round_trip(&[0x42]);
    }

    #[test]
    fn round_trip_short_text() {
        round_trip(b"the quick brown fox jumps over the lazy dog");
    }

    #[test]
    fn round_trip_elf_header_slice() {
        let elf: [u8; 32] = [
            0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x10, 0x40, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        round_trip(&elf);
    }

    #[test]
    fn round_trip_pe_header_slice() {
        let mut pe: Vec<u8> = vec![0u8; 64];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3c] = 0x40;
        pe.extend_from_slice(b"PE\x00\x00");
        round_trip(&pe);
    }

    #[test]
    fn round_trip_lcg_random_small() {
        round_trip(&lcg_bytes(0xdead_beef, 300));
    }

    #[test]
    fn round_trip_lcg_random_larger() {
        round_trip(&lcg_bytes(0x1234_5678, 4096));
    }

    #[test]
    fn round_trip_all_zero_exercises_rle() {
        let zeros: Vec<u8> = vec![0u8; ZERO_RUN * 3 + 100];
        round_trip(&zeros);
    }

    #[test]
    fn round_trip_zero_then_data() {
        let mut buf: Vec<u8> = vec![0u8; ZERO_RUN + 200];
        buf.extend_from_slice(b"payload after a zero run that is long enough to RLE");
        buf.extend_from_slice(&lcg_bytes(7, 500));
        round_trip(&buf);
    }

    #[test]
    fn round_trip_repeating_pattern_exercises_match_model() {
        let mut buf: Vec<u8> = Vec::new();
        let mut i: usize = 0;
        while i < 2000 {
            buf.extend_from_slice(b"ABCDEFGH");
            i += 1;
        }
        round_trip(&buf);
    }

    #[test]
    fn depack_rejects_oversize_request() {
        let r: Result<Vec<u8>> = rangecoder_depack(&[0, 0, 0, 0], OUTPUT_CAP + 1);
        assert!(matches!(r, Err(Error::SignatureDb(_))));
    }

    #[test]
    fn depack_rejects_truncated_header() {
        let r: Result<Vec<u8>> = rangecoder_depack(&[0, 0], 16);
        assert!(matches!(r, Err(Error::Truncated { .. })));
    }

    #[test]
    fn depack_truncated_stream_errors_not_panics() {
        let r: Result<Vec<u8>> = rangecoder_depack(&[0xff, 0xff, 0xff, 0xff], 4096);
        assert!(r.is_err());
    }
}
