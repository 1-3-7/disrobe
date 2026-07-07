use crate::error::{Error, Result};

const PPMD_NUM_INDEXES: usize = 38;
const UNIT_SIZE: u32 = 12;
const MAX_FREQ: u8 = 124;
const PPMD_BIN_SCALE: u32 = 1 << 14;
const PPMD_PERIOD_BITS: u32 = 7;
const PPMD_INT_BITS: u32 = 7;
const PPMD7_MAX_ORDER: usize = 64;
const RANGE_TOP: u32 = 1 << 24;
const RANGE_BOT: u32 = 1 << 15;

const K_EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];
const K_INIT_BIN_ESC: [u16; 8] = [
    0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051,
];

const STATE_SIZE: u32 = 6;

const fn get_mean_spec(summ: u32, shift: u32, round: u32) -> u32 {
    (summ + (1 << (shift - round))) >> shift
}

const fn get_mean(summ: u32) -> u32 {
    get_mean_spec(summ, PPMD_PERIOD_BITS, 2)
}

#[derive(Debug)]
struct Suballoc {
    base: Vec<u8>,
    size: u32,
    lo_unit: u32,
    hi_unit: u32,
    text: u32,
    units_start: u32,
    glue_count: u32,
    free_list: [u32; PPMD_NUM_INDEXES],
    indx2units: [u8; PPMD_NUM_INDEXES],
    units2indx: [u8; 128],
}

impl Suballoc {
    fn new(size: u32) -> Self {
        let mut indx2units: [u8; PPMD_NUM_INDEXES] = [0u8; PPMD_NUM_INDEXES];
        let mut units2indx: [u8; 128] = [0u8; 128];
        let mut k: usize = 0;
        for (i, slot) in indx2units.iter_mut().enumerate() {
            let mut step: usize = if i >= 12 { 4 } else { (i >> 2) + 1 };
            loop {
                units2indx[k] = i as u8;
                k += 1;
                step -= 1;
                if step == 0 {
                    break;
                }
            }
            *slot = k as u8;
        }
        let align_offset: u32 = 4u32.wrapping_sub(size) & 3;
        let alloc_len: usize = (align_offset + size + UNIT_SIZE) as usize;
        Self {
            base: vec![0u8; alloc_len],
            size,
            lo_unit: 0,
            hi_unit: 0,
            text: 0,
            units_start: 0,
            glue_count: 0,
            free_list: [0u32; PPMD_NUM_INDEXES],
            indx2units,
            units2indx,
        }
    }

    const fn align_offset(&self) -> u32 {
        4u32.wrapping_sub(self.size) & 3
    }

    fn i2u(&self, indx: usize) -> u32 {
        u32::from(self.indx2units[indx])
    }

    fn u2i(&self, nu: u32) -> usize {
        usize::from(self.units2indx[(nu - 1) as usize])
    }

    fn read_u32(&self, off: u32) -> u32 {
        let o: usize = off as usize;
        u32::from_le_bytes([
            self.base[o],
            self.base[o + 1],
            self.base[o + 2],
            self.base[o + 3],
        ])
    }

    fn write_u32(&mut self, off: u32, v: u32) {
        let o: usize = off as usize;
        self.base[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn node_next(&self, off: u32) -> u32 {
        self.read_u32(off)
    }

    fn node_set_next(&mut self, off: u32, v: u32) {
        self.write_u32(off, v);
    }

    fn node_nu(&self, off: u32) -> u16 {
        let o: usize = off as usize;
        u16::from_le_bytes([self.base[o + 2], self.base[o + 3]])
    }

    fn node_set_nu(&mut self, off: u32, v: u16) {
        let o: usize = off as usize;
        self.base[o + 2..o + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn node_stamp(&self, off: u32) -> u16 {
        let o: usize = off as usize;
        u16::from_le_bytes([self.base[o], self.base[o + 1]])
    }

    fn node_set_stamp(&mut self, off: u32, v: u16) {
        let o: usize = off as usize;
        self.base[o..o + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn node2_next(&self, off: u32) -> u32 {
        self.read_u32(off + 4)
    }

    fn node2_set_next(&mut self, off: u32, v: u32) {
        self.write_u32(off + 4, v);
    }

    fn node2_prev(&self, off: u32) -> u32 {
        self.read_u32(off + 8)
    }

    fn node2_set_prev(&mut self, off: u32, v: u32) {
        self.write_u32(off + 8, v);
    }

    fn insert_node(&mut self, node: u32, indx: usize) {
        let head: u32 = self.free_list[indx];
        self.node_set_next(node, head);
        self.free_list[indx] = node;
    }

    fn remove_node(&mut self, indx: usize) -> u32 {
        let node: u32 = self.free_list[indx];
        self.free_list[indx] = self.node_next(node);
        node
    }

    const fn u2b(nu: u32) -> u32 {
        nu * UNIT_SIZE
    }

    fn split_block(&mut self, ptr: u32, old_indx: usize, new_indx: usize) {
        let nu: u32 = self.i2u(old_indx) - self.i2u(new_indx);
        let ptr: u32 = ptr + Self::u2b(self.i2u(new_indx));
        let mut i: usize = self.u2i(nu);
        if self.i2u(i) != nu {
            i -= 1;
            let k: u32 = self.i2u(i);
            self.insert_node(ptr + Self::u2b(k), (nu - k - 1) as usize);
        }
        self.insert_node(ptr, i);
    }

    fn glue_free_blocks(&mut self) {
        let head: u32 = self.align_offset() + self.size;
        let mut n: u32 = head;
        self.glue_count = 255;
        for i in 0..PPMD_NUM_INDEXES {
            let nu: u16 = self.i2u(i) as u16;
            let mut next: u32 = self.free_list[i];
            self.free_list[i] = 0;
            while next != 0 {
                let node: u32 = next;
                self.node2_set_next(node, n);
                self.node2_set_prev(n, node);
                n = node;
                next = self.node_next(node);
                self.node_set_stamp(node, 0);
                self.node_set_nu(node, nu);
            }
        }
        self.node_set_stamp(head, 1);
        self.node2_set_next(head, n);
        self.node2_set_prev(n, head);
        if self.lo_unit != self.hi_unit {
            self.node_set_stamp(self.lo_unit, 1);
        }
        while n != head {
            let mut nu: u32 = u32::from(self.node_nu(n));
            loop {
                let node2: u32 = n + Self::u2b(nu);
                let n2_nu: u32 = u32::from(self.node_nu(node2));
                let combined: u32 = nu + n2_nu;
                if self.node_stamp(node2) != 0 || combined >= 0x10000 {
                    break;
                }
                let p2: u32 = self.node2_prev(node2);
                let nx: u32 = self.node2_next(node2);
                self.node2_set_next(p2, nx);
                self.node2_set_prev(nx, p2);
                nu = combined;
                self.node_set_nu(n, nu as u16);
            }
            n = self.node2_next(n);
        }
        let mut cur: u32 = self.node2_next(head);
        while cur != head {
            let next: u32 = self.node2_next(cur);
            let mut nu: u32 = u32::from(self.node_nu(cur));
            let mut node: u32 = cur;
            while nu > 128 {
                self.insert_node(node, PPMD_NUM_INDEXES - 1);
                nu -= 128;
                node += Self::u2b(128);
            }
            let mut i: usize = self.u2i(nu);
            if self.i2u(i) != nu {
                i -= 1;
                let k: u32 = self.i2u(i);
                self.insert_node(node + Self::u2b(k), (nu - k - 1) as usize);
            }
            self.insert_node(node, i);
            cur = next;
        }
    }

    fn alloc_units_rare(&mut self, indx: usize) -> u32 {
        if self.glue_count == 0 {
            self.glue_free_blocks();
            if self.free_list[indx] != 0 {
                return self.remove_node(indx);
            }
        }
        let mut i: usize = indx;
        loop {
            i += 1;
            if i == PPMD_NUM_INDEXES {
                let num_bytes: u32 = Self::u2b(self.i2u(indx));
                self.glue_count -= 1;
                if self.units_start - self.text > num_bytes {
                    self.units_start -= num_bytes;
                    return self.units_start;
                }
                return 0;
            }
            if self.free_list[i] != 0 {
                break;
            }
        }
        let ret: u32 = self.remove_node(i);
        self.split_block(ret, i, indx);
        ret
    }

    fn alloc_units(&mut self, indx: usize) -> u32 {
        if self.free_list[indx] != 0 {
            return self.remove_node(indx);
        }
        let num_bytes: u32 = Self::u2b(self.i2u(indx));
        if num_bytes <= self.hi_unit - self.lo_unit {
            let ret: u32 = self.lo_unit;
            self.lo_unit += num_bytes;
            return ret;
        }
        self.alloc_units_rare(indx)
    }

    fn shrink_units(&mut self, old_ptr: u32, old_nu: u32, new_nu: u32) -> u32 {
        let i0: usize = self.u2i(old_nu);
        let i1: usize = self.u2i(new_nu);
        if i0 == i1 {
            return old_ptr;
        }
        if self.free_list[i1] != 0 {
            let ptr: u32 = self.remove_node(i1);
            self.mem12_copy(ptr, old_ptr, new_nu);
            self.insert_node(old_ptr, i0);
            ptr
        } else {
            self.split_block(old_ptr, i0, i1);
            old_ptr
        }
    }

    fn mem12_copy(&mut self, dest: u32, src: u32, nu: u32) {
        let n: usize = (nu * UNIT_SIZE) as usize;
        let d: usize = dest as usize;
        let s: usize = src as usize;
        self.base.copy_within(s..s + n, d);
    }
}

struct See {
    summ: u16,
    shift: u8,
    count: u8,
}

struct Ppmd7 {
    sa: Suballoc,
    min_context: u32,
    max_context: u32,
    found_state: u32,
    order_fall: u32,
    init_esc: u32,
    prev_success: u32,
    max_order: u32,
    hi_bits_flag: u32,
    run_length: i32,
    init_rl: i32,
    ns2indx: [u8; 256],
    ns2bsindx: [u8; 256],
    hb2flag: [u8; 256],
    dummy_see: See,
    see: Vec<See>,
    bin_summ: [[u16; 64]; 128],
}

impl Ppmd7 {
    fn new(max_order: u32, mem_size: u32) -> Self {
        let mut ns2indx: [u8; 256] = [0u8; 256];
        let mut ns2bsindx: [u8; 256] = [0u8; 256];
        let mut hb2flag: [u8; 256] = [0u8; 256];
        ns2bsindx[0] = 0;
        ns2bsindx[1] = 2;
        for slot in ns2bsindx.iter_mut().skip(2).take(9) {
            *slot = 4;
        }
        for slot in ns2bsindx.iter_mut().skip(11) {
            *slot = 6;
        }
        for (i, slot) in ns2indx.iter_mut().enumerate().take(3) {
            *slot = i as u8;
        }
        let mut m: u8 = 3;
        let mut k: u8 = 1;
        for slot in ns2indx.iter_mut().take(256).skip(3) {
            *slot = m;
            k -= 1;
            if k == 0 {
                m += 1;
                k = m - 2;
            }
        }
        for slot in hb2flag.iter_mut().skip(0x40) {
            *slot = 8;
        }
        let mut see: Vec<See> = Vec::with_capacity(25 * 16);
        for _ in 0..25 * 16 {
            see.push(See {
                summ: 0,
                shift: 0,
                count: 0,
            });
        }
        Self {
            sa: Suballoc::new(mem_size),
            min_context: 0,
            max_context: 0,
            found_state: 0,
            order_fall: 0,
            init_esc: 0,
            prev_success: 0,
            max_order,
            hi_bits_flag: 0,
            run_length: 0,
            init_rl: 0,
            ns2indx,
            ns2bsindx,
            hb2flag,
            dummy_see: See {
                summ: 0,
                shift: PPMD_PERIOD_BITS as u8,
                count: 64,
            },
            see,
            bin_summ: [[0u16; 64]; 128],
        }
    }

    fn ctx_num_stats(&self, c: u32) -> u16 {
        let o: usize = c as usize;
        u16::from_le_bytes([self.sa.base[o], self.sa.base[o + 1]])
    }

    fn ctx_set_num_stats(&mut self, c: u32, v: u16) {
        let o: usize = c as usize;
        self.sa.base[o..o + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn ctx_summ_freq(&self, c: u32) -> u16 {
        let o: usize = (c + 2) as usize;
        u16::from_le_bytes([self.sa.base[o], self.sa.base[o + 1]])
    }

    fn ctx_set_summ_freq(&mut self, c: u32, v: u16) {
        let o: usize = (c + 2) as usize;
        self.sa.base[o..o + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn ctx_stats(&self, c: u32) -> u32 {
        self.sa.read_u32(c + 4)
    }

    fn ctx_set_stats(&mut self, c: u32, v: u32) {
        self.sa.write_u32(c + 4, v);
    }

    fn ctx_suffix(&self, c: u32) -> u32 {
        self.sa.read_u32(c + 8)
    }

    fn ctx_set_suffix(&mut self, c: u32, v: u32) {
        self.sa.write_u32(c + 8, v);
    }

    const fn one_state(c: u32) -> u32 {
        c + 2
    }

    fn st_symbol(&self, s: u32) -> u8 {
        self.sa.base[s as usize]
    }

    fn st_set_symbol(&mut self, s: u32, v: u8) {
        self.sa.base[s as usize] = v;
    }

    fn st_freq(&self, s: u32) -> u8 {
        self.sa.base[(s + 1) as usize]
    }

    fn st_set_freq(&mut self, s: u32, v: u8) {
        self.sa.base[(s + 1) as usize] = v;
    }

    fn st_successor(&self, s: u32) -> u32 {
        let o: usize = (s + 2) as usize;
        let lo: u32 = u32::from(u16::from_le_bytes([self.sa.base[o], self.sa.base[o + 1]]));
        let hi: u32 = u32::from(u16::from_le_bytes([
            self.sa.base[o + 2],
            self.sa.base[o + 3],
        ]));
        lo | (hi << 16)
    }

    fn st_set_successor(&mut self, s: u32, v: u32) {
        let o: usize = (s + 2) as usize;
        let lo: u16 = (v & 0xFFFF) as u16;
        let hi: u16 = ((v >> 16) & 0xFFFF) as u16;
        self.sa.base[o..o + 2].copy_from_slice(&lo.to_le_bytes());
        self.sa.base[o + 2..o + 4].copy_from_slice(&hi.to_le_bytes());
    }

    fn copy_state(&mut self, dest: u32, src: u32) {
        let d: usize = dest as usize;
        let s: usize = src as usize;
        self.sa.base.copy_within(s..s + STATE_SIZE as usize, d);
    }

    fn restart_model(&mut self) {
        self.sa.free_list = [0u32; PPMD_NUM_INDEXES];
        self.sa.text = self.sa.align_offset();
        self.sa.hi_unit = self.sa.text + self.sa.size;
        self.sa.lo_unit = self.sa.hi_unit - self.sa.size / 8 / UNIT_SIZE * 7 * UNIT_SIZE;
        self.sa.units_start = self.sa.lo_unit;
        self.sa.glue_count = 0;

        self.order_fall = self.max_order;
        self.init_rl = -(if self.max_order < 12 {
            self.max_order
        } else {
            12
        } as i32)
            - 1;
        self.run_length = self.init_rl;
        self.prev_success = 0;

        self.sa.hi_unit -= UNIT_SIZE;
        let mc: u32 = self.sa.hi_unit;
        self.min_context = mc;
        self.max_context = mc;
        self.ctx_set_suffix(mc, 0);
        self.ctx_set_num_stats(mc, 256);
        self.ctx_set_summ_freq(mc, 256 + 1);
        let fs: u32 = self.sa.lo_unit;
        self.found_state = fs;
        self.sa.lo_unit += Suballoc::u2b(256 / 2);
        self.ctx_set_stats(mc, fs);
        for i in 0..256u32 {
            let s: u32 = fs + i * STATE_SIZE;
            self.st_set_symbol(s, i as u8);
            self.st_set_freq(s, 1);
            self.st_set_successor(s, 0);
        }

        for i in 0..128usize {
            for (k, &esc) in K_INIT_BIN_ESC.iter().enumerate() {
                let val: u16 = (PPMD_BIN_SCALE - u32::from(esc) / (i as u32 + 2)) as u16;
                let mut m: usize = 0;
                while m < 64 {
                    self.bin_summ[i][k + m] = val;
                    m += 8;
                }
            }
        }
        for i in 0..25usize {
            for k in 0..16usize {
                let s: &mut See = &mut self.see[i * 16 + k];
                s.shift = (PPMD_PERIOD_BITS - 4) as u8;
                s.summ = (((5 * i + 10) as u32) << s.shift) as u16;
                s.count = 4;
            }
        }
    }

    fn create_successors(&mut self, skip: bool) -> u32 {
        let mut c: u32 = self.min_context;
        let up_branch: u32 = self.st_successor(self.found_state);
        let mut ps: [u32; PPMD7_MAX_ORDER] = [0u32; PPMD7_MAX_ORDER];
        let mut num_ps: usize = 0;

        if !skip {
            ps[num_ps] = self.found_state;
            num_ps += 1;
        }

        while self.ctx_suffix(c) != 0 {
            c = self.ctx_suffix(c);
            let s: u32 = if self.ctx_num_stats(c) == 1 {
                Self::one_state(c)
            } else {
                let mut sp: u32 = self.ctx_stats(c);
                let target: u8 = self.st_symbol(self.found_state);
                while self.st_symbol(sp) != target {
                    sp += STATE_SIZE;
                }
                sp
            };
            let successor: u32 = self.st_successor(s);
            if successor != up_branch {
                c = successor;
                if num_ps == 0 {
                    return c;
                }
                break;
            }
            ps[num_ps] = s;
            num_ps += 1;
        }

        let up_symbol: u8 = self.sa.base[up_branch as usize];
        let up_successor: u32 = up_branch + 1;
        let up_freq: u8 = if self.ctx_num_stats(c) == 1 {
            self.st_freq(Self::one_state(c))
        } else {
            let mut sp: u32 = self.ctx_stats(c);
            while self.st_symbol(sp) != up_symbol {
                sp += STATE_SIZE;
            }
            let cf: u32 = u32::from(self.st_freq(sp)) - 1;
            let s0: u32 = u32::from(self.ctx_summ_freq(c)) - u32::from(self.ctx_num_stats(c)) - cf;
            (1 + if 2 * cf <= s0 {
                u32::from(5 * cf > s0)
            } else {
                (2 * cf + 3 * s0 - 1) / (2 * s0)
            }) as u8
        };

        loop {
            let c1: u32 = if self.sa.hi_unit != self.sa.lo_unit {
                self.sa.hi_unit -= UNIT_SIZE;
                self.sa.hi_unit
            } else if self.sa.free_list[0] != 0 {
                self.sa.remove_node(0)
            } else {
                let r: u32 = self.sa.alloc_units_rare(0);
                if r == 0 {
                    return 0;
                }
                r
            };
            self.ctx_set_num_stats(c1, 1);
            let os: u32 = Self::one_state(c1);
            self.st_set_symbol(os, up_symbol);
            self.st_set_freq(os, up_freq);
            self.st_set_successor(os, up_successor);
            self.ctx_set_suffix(c1, c);
            num_ps -= 1;
            self.st_set_successor(ps[num_ps], c1);
            c = c1;
            if num_ps == 0 {
                break;
            }
        }
        c
    }

    fn swap_states(&mut self, a: u32, b: u32) {
        for i in 0..STATE_SIZE {
            self.sa.base.swap((a + i) as usize, (b + i) as usize);
        }
    }

    fn rescale(&mut self) {
        let stats: u32 = self.ctx_stats(self.min_context);
        let mut s: u32 = self.found_state;
        {
            let mut tmp: [u8; STATE_SIZE as usize] = [0u8; STATE_SIZE as usize];
            tmp.copy_from_slice(&self.sa.base[s as usize..(s + STATE_SIZE) as usize]);
            while s != stats {
                self.copy_state(s, s - STATE_SIZE);
                s -= STATE_SIZE;
            }
            self.sa.base[s as usize..(s + STATE_SIZE) as usize].copy_from_slice(&tmp);
        }
        let mut esc_freq: u32 =
            u32::from(self.ctx_summ_freq(self.min_context)) - u32::from(self.st_freq(s));
        let new_freq: u8 = self.st_freq(s) + 4;
        self.st_set_freq(s, new_freq);
        let adder: u32 = u32::from(self.order_fall != 0);
        let halved: u8 = ((u32::from(self.st_freq(s)) + adder) >> 1) as u8;
        self.st_set_freq(s, halved);
        let mut sum_freq: u32 = u32::from(halved);

        let mut i: u32 = u32::from(self.ctx_num_stats(self.min_context)) - 1;
        while i != 0 {
            s += STATE_SIZE;
            esc_freq -= u32::from(self.st_freq(s));
            let hv: u8 = ((u32::from(self.st_freq(s)) + adder) >> 1) as u8;
            self.st_set_freq(s, hv);
            sum_freq += u32::from(hv);
            if self.st_freq(s) > self.st_freq(s - STATE_SIZE) {
                let mut s1: u32 = s;
                let mut tmp: [u8; STATE_SIZE as usize] = [0u8; STATE_SIZE as usize];
                tmp.copy_from_slice(&self.sa.base[s1 as usize..(s1 + STATE_SIZE) as usize]);
                let tmp_freq: u8 = tmp[1];
                loop {
                    self.copy_state(s1, s1 - STATE_SIZE);
                    s1 -= STATE_SIZE;
                    if s1 == stats || tmp_freq <= self.st_freq(s1 - STATE_SIZE) {
                        break;
                    }
                }
                self.sa.base[s1 as usize..(s1 + STATE_SIZE) as usize].copy_from_slice(&tmp);
            }
            i -= 1;
        }

        if self.st_freq(s) == 0 {
            let num_stats: u32 = u32::from(self.ctx_num_stats(self.min_context));
            let mut cnt: u32 = 0;
            loop {
                cnt += 1;
                s -= STATE_SIZE;
                if self.st_freq(s) != 0 {
                    break;
                }
            }
            esc_freq += cnt;
            let new_ns: u16 = self.ctx_num_stats(self.min_context) - cnt as u16;
            self.ctx_set_num_stats(self.min_context, new_ns);
            if new_ns == 1 {
                let mut tmp: [u8; STATE_SIZE as usize] = [0u8; STATE_SIZE as usize];
                tmp.copy_from_slice(&self.sa.base[stats as usize..(stats + STATE_SIZE) as usize]);
                let mut tmp_freq: u8 = tmp[1];
                loop {
                    tmp_freq = (u32::from(tmp_freq) - (u32::from(tmp_freq) >> 1)) as u8;
                    esc_freq >>= 1;
                    if esc_freq <= 1 {
                        break;
                    }
                }
                tmp[1] = tmp_freq;
                self.sa
                    .insert_node(stats, self.sa.u2i((num_stats + 1) >> 1));
                let os: u32 = Self::one_state(self.min_context);
                self.found_state = os;
                self.sa.base[os as usize..(os + STATE_SIZE) as usize].copy_from_slice(&tmp);
                return;
            }
            let n0: u32 = (num_stats + 1) >> 1;
            let n1: u32 = (u32::from(new_ns) + 1) >> 1;
            if n0 != n1 {
                let new_stats: u32 = self.sa.shrink_units(stats, n0, n1);
                self.ctx_set_stats(self.min_context, new_stats);
            }
        }
        let final_summ: u16 = (sum_freq + esc_freq - (esc_freq >> 1)) as u16;
        self.ctx_set_summ_freq(self.min_context, final_summ);
        self.found_state = self.ctx_stats(self.min_context);
    }

    fn update_model(&mut self) {
        let mut f_successor: u32 = self.st_successor(self.found_state);
        let fs_symbol: u8 = self.st_symbol(self.found_state);
        let fs_freq: u8 = self.st_freq(self.found_state);
        let mut c: u32;

        if fs_freq < MAX_FREQ / 4 && self.ctx_suffix(self.min_context) != 0 {
            c = self.ctx_suffix(self.min_context);
            if self.ctx_num_stats(c) == 1 {
                let s: u32 = Self::one_state(c);
                if self.st_freq(s) < 32 {
                    self.st_set_freq(s, self.st_freq(s) + 1);
                }
            } else {
                let mut s: u32 = self.ctx_stats(c);
                if self.st_symbol(s) != fs_symbol {
                    loop {
                        s += STATE_SIZE;
                        if self.st_symbol(s) == fs_symbol {
                            break;
                        }
                    }
                    if self.st_freq(s) >= self.st_freq(s - STATE_SIZE) {
                        self.swap_states(s, s - STATE_SIZE);
                        s -= STATE_SIZE;
                    }
                }
                if self.st_freq(s) < MAX_FREQ - 9 {
                    self.st_set_freq(s, self.st_freq(s) + 2);
                    self.ctx_set_summ_freq(c, self.ctx_summ_freq(c) + 2);
                }
            }
        }

        if self.order_fall == 0 {
            let cs: u32 = self.create_successors(true);
            if cs == 0 {
                self.restart_model();
                return;
            }
            self.min_context = cs;
            self.max_context = cs;
            self.st_set_successor(self.found_state, cs);
            return;
        }

        self.sa.base[self.sa.text as usize] = fs_symbol;
        self.sa.text += 1;
        let mut successor: u32 = self.sa.text;
        if self.sa.text >= self.sa.units_start {
            self.restart_model();
            return;
        }

        if f_successor != 0 {
            if f_successor <= successor {
                let cs: u32 = self.create_successors(false);
                if cs == 0 {
                    self.restart_model();
                    return;
                }
                f_successor = cs;
            }
            self.order_fall -= 1;
            if self.order_fall == 0 {
                successor = f_successor;
                if self.max_context != self.min_context {
                    self.sa.text -= 1;
                }
            }
        } else {
            self.st_set_successor(self.found_state, successor);
            f_successor = self.min_context;
        }

        let ns: u32 = u32::from(self.ctx_num_stats(self.min_context));
        let s0: u32 =
            u32::from(self.ctx_summ_freq(self.min_context)) - ns - (u32::from(fs_freq) - 1);

        c = self.max_context;
        while c != self.min_context {
            let mut ns1: u32 = u32::from(self.ctx_num_stats(c));
            if ns1 == 1 {
                let new_s: u32 = self.sa.alloc_units(0);
                if new_s == 0 {
                    self.restart_model();
                    return;
                }
                let os: u32 = Self::one_state(c);
                self.copy_state(new_s, os);
                self.ctx_set_stats(c, new_s);
                let nf: u8 = if self.st_freq(new_s) < MAX_FREQ / 4 - 1 {
                    self.st_freq(new_s).wrapping_add(self.st_freq(new_s))
                } else {
                    MAX_FREQ - 4
                };
                self.st_set_freq(new_s, nf);
                let summ: u32 = u32::from(nf) + self.init_esc + u32::from(ns > 3);
                self.ctx_set_summ_freq(c, summ as u16);
            } else {
                if (ns1 & 1) == 0 {
                    let old_nu: u32 = ns1 >> 1;
                    let i: usize = self.sa.u2i(old_nu);
                    if i != self.sa.u2i(old_nu + 1) {
                        let ptr: u32 = self.sa.alloc_units(i + 1);
                        if ptr == 0 {
                            self.restart_model();
                            return;
                        }
                        let old_ptr: u32 = self.ctx_stats(c);
                        self.sa.mem12_copy(ptr, old_ptr, old_nu);
                        self.sa.insert_node(old_ptr, i);
                        self.ctx_set_stats(c, ptr);
                    }
                }
                let add: u32 = u32::from(2 * ns1 < ns)
                    + 2 * (u32::from(
                        (4 * ns1 <= ns) && (u32::from(self.ctx_summ_freq(c)) <= 8 * ns1),
                    ));
                self.ctx_set_summ_freq(c, (u32::from(self.ctx_summ_freq(c)) + add) as u16);
            }
            let cf: u32 = 2 * u32::from(fs_freq) * (u32::from(self.ctx_summ_freq(c)) + 6);
            let sf: u32 = s0 + u32::from(self.ctx_summ_freq(c));
            let final_cf: u32 = if cf < 6 * sf {
                self.ctx_set_summ_freq(c, self.ctx_summ_freq(c) + 3);
                1 + u32::from(cf > sf) + u32::from(cf >= 4 * sf)
            } else {
                let computed: u32 = 4
                    + u32::from(cf >= 9 * sf)
                    + u32::from(cf >= 12 * sf)
                    + u32::from(cf >= 15 * sf);
                self.ctx_set_summ_freq(c, (u32::from(self.ctx_summ_freq(c)) + computed) as u16);
                computed
            };
            let s: u32 = self.ctx_stats(c) + ns1 * STATE_SIZE;
            self.st_set_successor(s, successor);
            self.st_set_symbol(s, fs_symbol);
            self.st_set_freq(s, final_cf as u8);
            ns1 += 1;
            self.ctx_set_num_stats(c, ns1 as u16);
            c = self.ctx_suffix(c);
        }
        self.max_context = f_successor;
        self.min_context = f_successor;
    }

    fn next_context(&mut self) {
        let c: u32 = self.st_successor(self.found_state);
        if self.order_fall == 0 && c > self.sa.text {
            self.min_context = c;
            self.max_context = c;
        } else {
            self.update_model();
        }
    }

    fn update1(&mut self) {
        let mut s: u32 = self.found_state;
        self.st_set_freq(s, self.st_freq(s) + 4);
        self.ctx_set_summ_freq(self.min_context, self.ctx_summ_freq(self.min_context) + 4);
        if self.st_freq(s) > self.st_freq(s - STATE_SIZE) {
            self.swap_states(s, s - STATE_SIZE);
            s -= STATE_SIZE;
            self.found_state = s;
            if self.st_freq(s) > MAX_FREQ {
                self.rescale();
            }
        }
        self.next_context();
    }

    fn update_bin(&mut self) {
        let fs: u32 = self.found_state;
        let f: u8 = self.st_freq(fs);
        self.st_set_freq(fs, f + u8::from(f < 128));
        self.prev_success = 1;
        self.run_length += 1;
        self.next_context();
    }

    fn update2(&mut self) {
        let fs: u32 = self.found_state;
        self.ctx_set_summ_freq(self.min_context, self.ctx_summ_freq(self.min_context) + 4);
        let nf: u8 = self.st_freq(fs) + 4;
        self.st_set_freq(fs, nf);
        if nf > MAX_FREQ {
            self.rescale();
        }
        self.run_length = self.init_rl;
        self.update_model();
    }

    fn make_esc_freq(&mut self, num_masked: u32) -> (SeeRef, u32) {
        let num_stats: u32 = u32::from(self.ctx_num_stats(self.min_context));
        let non_masked: u32 = num_stats - num_masked;
        if num_stats == 256 {
            return (SeeRef::Dummy, 1);
        }
        let suffix_ns: u32 = u32::from(self.ctx_num_stats(self.ctx_suffix(self.min_context)));
        let idx: usize = usize::from(self.ns2indx[(non_masked - 1) as usize]) * 16
            + usize::from(non_masked < suffix_ns - num_stats)
            + 2 * usize::from(u32::from(self.ctx_summ_freq(self.min_context)) < 11 * num_stats)
            + 4 * usize::from(num_masked > non_masked)
            + self.hi_bits_flag as usize;
        let r: u32 = u32::from(self.see[idx].summ) >> self.see[idx].shift;
        self.see[idx].summ = (u32::from(self.see[idx].summ) - r) as u16;
        (SeeRef::Index(idx), r + u32::from(r == 0))
    }

    fn see_update(&mut self, see: SeeRef) {
        if let SeeRef::Index(idx) = see {
            let s: &mut See = &mut self.see[idx];
            if u32::from(s.shift) < PPMD_PERIOD_BITS {
                s.count -= 1;
                if s.count == 0 {
                    s.summ = s.summ.wrapping_shl(1);
                    s.count = (3u32 << s.shift) as u8;
                    s.shift += 1;
                }
            }
        }
    }

    fn see_summ_add(&mut self, see: SeeRef, add: u32) {
        match see {
            SeeRef::Index(idx) => {
                self.see[idx].summ = (u32::from(self.see[idx].summ) + add) as u16;
            }
            SeeRef::Dummy => {
                self.dummy_see.summ = (u32::from(self.dummy_see.summ) + add) as u16;
            }
        }
    }

    fn bin_summ_ref(&self) -> (usize, usize) {
        let one: u32 = Self::one_state(self.min_context);
        let row: usize = (u32::from(self.st_freq(one)) - 1) as usize;
        let suffix_ns: u32 = u32::from(self.ctx_num_stats(self.ctx_suffix(self.min_context)));
        let col: usize = self.prev_success as usize
            + usize::from(self.ns2bsindx[(suffix_ns - 1) as usize])
            + self.hi_bits_flag as usize
            + 2 * usize::from(self.hb2flag[self.st_symbol(one) as usize])
            + ((self.run_length >> 26) & 0x20) as usize;
        (row, col)
    }
}

#[derive(Clone, Copy)]
enum SeeRef {
    Index(usize),
    Dummy,
}

struct RangeDec<'a> {
    data: &'a [u8],
    pos: usize,
    low: u32,
    code: u32,
    range: u32,
}

impl<'a> RangeDec<'a> {
    fn new(data: &'a [u8]) -> Self {
        let mut rd: Self = Self {
            data,
            pos: 0,
            low: 0,
            code: 0,
            range: 0xFFFF_FFFF,
        };
        for _ in 0..4 {
            rd.code = (rd.code << 8) | u32::from(rd.next_byte());
        }
        rd
    }

    fn next_byte(&mut self) -> u8 {
        let b: u8 = self
            .data
            .get(self.pos)
            .copied()
            .map_or(0, |value: u8| value);
        self.pos += 1;
        b
    }

    const fn get_current_count(&mut self, scale: u32) -> u32 {
        if scale == 0 {
            return u32::MAX;
        }
        self.range /= scale;
        if self.range == 0 {
            return u32::MAX;
        }
        self.code.wrapping_sub(self.low) / self.range
    }

    const fn get_current_shift_count(&mut self, shift: u32) -> u32 {
        self.range >>= shift;
        if self.range == 0 {
            return u32::MAX;
        }
        self.code.wrapping_sub(self.low) / self.range
    }

    fn decode(&mut self, low_count: u32, high_count: u32) {
        self.low = self.low.wrapping_add(self.range.wrapping_mul(low_count));
        self.range = self.range.wrapping_mul(high_count - low_count);
        self.normalize();
    }

    fn normalize(&mut self) {
        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) < RANGE_TOP {
            } else if self.range < RANGE_BOT {
                self.range = self.low.wrapping_neg() & (RANGE_BOT - 1);
            } else {
                break;
            }
            self.code = (self.code << 8) | u32::from(self.next_byte());
            self.range <<= 8;
            self.low <<= 8;
        }
    }
}

struct DecodeCtx<'a> {
    model: Ppmd7,
    rc: RangeDec<'a>,
    char_mask: [u8; 256],
    esc_count: u8,
    num_masked: u32,
}

impl DecodeCtx<'_> {
    fn decode_bin_symbol(&mut self) -> i32 {
        let one: u32 = Ppmd7::one_state(self.model.min_context);
        self.model.hi_bits_flag =
            u32::from(self.model.hb2flag[self.model.st_symbol(self.model.found_state) as usize]);
        let (row, col): (usize, usize) = self.model.bin_summ_ref();
        let bs: u16 = self.model.bin_summ[row][col];
        let mean: u32 = get_mean(u32::from(bs));
        if self.rc.get_current_shift_count(14) < u32::from(bs) {
            self.rc.decode(0, u32::from(bs));
            self.model.found_state = one;
            self.model.bin_summ[row][col] = (u32::from(bs) + (1 << PPMD_INT_BITS) - mean) as u16;
            let sym: u8 = self.model.st_symbol(one);
            self.model.update_bin();
            i32::from(sym)
        } else {
            self.rc.decode(u32::from(bs), PPMD_BIN_SCALE);
            self.model.bin_summ[row][col] = (u32::from(bs) - mean) as u16;
            self.model.init_esc =
                u32::from(K_EXP_ESCAPE[(self.model.bin_summ[row][col] >> 10) as usize]);
            self.num_masked = 1;
            self.char_mask = [0u8; 256];
            self.char_mask[self.model.st_symbol(one) as usize] = self.esc_count;
            self.model.prev_success = 0;
            self.model.found_state = 0;
            -1
        }
    }

    fn decode_symbol1(&mut self) -> i32 {
        let mc: u32 = self.model.min_context;
        let scale: u32 = u32::from(self.model.ctx_summ_freq(mc));
        let count: u32 = self.rc.get_current_count(scale);
        if count >= scale {
            return -2;
        }
        let mut s: u32 = self.model.ctx_stats(mc);
        let mut hi_cnt: u32 = u32::from(self.model.st_freq(s));
        if count < hi_cnt {
            self.model.prev_success = u32::from(2 * hi_cnt > scale);
            self.model.run_length += self.model.prev_success as i32;
            self.model.found_state = s;
            let nf: u8 = self.model.st_freq(s) + 4;
            self.model.st_set_freq(s, nf);
            self.model
                .ctx_set_summ_freq(mc, self.model.ctx_summ_freq(mc) + 4);
            if nf > MAX_FREQ {
                self.model.rescale();
            }
            self.rc.decode(0, hi_cnt);
            self.model.next_context();
            return i32::from(self.model.st_symbol(self.model.found_state));
        }
        self.model.prev_success = 0;
        let mut i: u32 = u32::from(self.model.ctx_num_stats(mc)) - 1;
        loop {
            s += STATE_SIZE;
            let f: u32 = u32::from(self.model.st_freq(s));
            if hi_cnt + f > count {
                hi_cnt += f;
                self.rc.decode(hi_cnt - f, hi_cnt);
                self.model.found_state = s;
                self.model.update1();
                return i32::from(self.model.st_symbol(self.model.found_state));
            }
            hi_cnt += f;
            i -= 1;
            if i == 0 {
                break;
            }
        }
        self.model.hi_bits_flag =
            u32::from(self.model.hb2flag[self.model.st_symbol(self.model.found_state) as usize]);
        self.rc.decode(hi_cnt, scale);
        self.char_mask = [0u8; 256];
        self.char_mask[self.model.st_symbol(s) as usize] = self.esc_count;
        let mut j: u32 = u32::from(self.model.ctx_num_stats(mc)) - 1;
        let mut sp: u32 = s;
        while j != 0 {
            sp -= STATE_SIZE;
            self.char_mask[self.model.st_symbol(sp) as usize] = self.esc_count;
            j -= 1;
        }
        self.num_masked = u32::from(self.model.ctx_num_stats(mc));
        self.model.found_state = 0;
        -1
    }

    fn decode_symbol2(&mut self) -> i32 {
        let mc: u32 = self.model.min_context;
        let diff: u32 = u32::from(self.model.ctx_num_stats(mc)) - self.num_masked;
        let (see, mut scale): (SeeRef, u32) = self.model.make_esc_freq(self.num_masked);
        let mut ps: [u32; 256] = [0u32; 256];
        let mut num_ps: usize = 0;
        let mut hi_cnt: u32 = 0;
        let mut s: u32 = self.model.ctx_stats(mc);
        let mut remaining: u32 = diff;
        loop {
            while self.char_mask[self.model.st_symbol(s) as usize] == self.esc_count {
                s += STATE_SIZE;
            }
            hi_cnt += u32::from(self.model.st_freq(s));
            ps[num_ps] = s;
            num_ps += 1;
            s += STATE_SIZE;
            remaining -= 1;
            if remaining == 0 {
                break;
            }
        }
        scale += hi_cnt;
        let count: u32 = self.rc.get_current_count(scale);
        if count >= scale {
            return -2;
        }
        if count < hi_cnt {
            let mut idx: usize = 0;
            let mut acc: u32 = u32::from(self.model.st_freq(ps[0]));
            while acc <= count {
                idx += 1;
                acc += u32::from(self.model.st_freq(ps[idx]));
            }
            let chosen: u32 = ps[idx];
            let f: u32 = u32::from(self.model.st_freq(chosen));
            self.rc.decode(acc - f, acc);
            self.model.see_update(see);
            self.model.found_state = chosen;
            self.model.update2();
            i32::from(self.model.st_symbol(self.model.found_state))
        } else {
            self.rc.decode(hi_cnt, scale);
            for &p in ps.iter().take(num_ps) {
                self.char_mask[self.model.st_symbol(p) as usize] = self.esc_count;
            }
            self.model.see_summ_add(see, scale);
            self.num_masked = u32::from(self.model.ctx_num_stats(mc));
            -1
        }
    }

    fn decode_char(&mut self) -> i32 {
        if self.model.min_context <= self.model.sa.text {
            return -1;
        }
        if self.model.ctx_num_stats(self.model.min_context) == 1 {
            let r: i32 = self.decode_bin_symbol();
            if r != -1 {
                return r;
            }
        } else {
            let stats: u32 = self.model.ctx_stats(self.model.min_context);
            if stats <= self.model.sa.text {
                return -1;
            }
            let r: i32 = self.decode_symbol1();
            if r != -1 {
                return r;
            }
        }
        loop {
            loop {
                self.model.order_fall += 1;
                let suffix: u32 = self.model.ctx_suffix(self.model.min_context);
                if suffix == 0 {
                    return -1;
                }
                self.model.min_context = suffix;
                if self.model.min_context <= self.model.sa.text {
                    return -1;
                }
                if u32::from(self.model.ctx_num_stats(self.model.min_context)) != self.num_masked {
                    break;
                }
            }
            let r: i32 = self.decode_symbol2();
            if r != -1 {
                return r;
            }
        }
    }
}

fn copy_string(out: &mut Vec<u8>, length: u32, distance: u32, want: usize) -> Result<()> {
    let dist: usize = distance as usize;
    if dist == 0 || dist > out.len() {
        return Err(Error::Decompression(format!(
            "rar 2.9/3.x ppmd match distance {dist} out of range (have {} bytes)",
            out.len()
        )));
    }
    let mut remaining: usize = length as usize;
    let mut src: usize = out.len() - dist;
    while remaining > 0 && out.len() < want {
        let byte: u8 = out[src];
        out.push(byte);
        src += 1;
        remaining -= 1;
    }
    Ok(())
}

pub fn unpack3_ppmd(packed: &[u8], unpacked_size: u64, cap: u64) -> Result<Vec<u8>> {
    if unpacked_size > cap {
        return Err(Error::Decompression(format!(
            "rar 2.9/3.x ppmd unpacked size {unpacked_size} exceeds cap {cap}"
        )));
    }
    let want: usize = usize::try_from(unpacked_size).map_err(|_e: std::num::TryFromIntError| {
        Error::Decompression("rar 2.9/3.x ppmd size overflow".to_owned())
    })?;

    let mut hdr_pos: usize = 0;
    let read_byte = |pos: &mut usize| -> Result<u8> {
        let b: u8 = *packed
            .get(*pos)
            .ok_or_else(|| Error::Decompression("rar 2.9/3.x ppmd header truncated".to_owned()))?;
        *pos += 1;
        Ok(b)
    };

    let max_order_raw: u8 = read_byte(&mut hdr_pos)?;
    let reset: bool = (max_order_raw & 0x20) != 0;
    if !reset {
        return Err(Error::Decompression(
            "rar 2.9/3.x ppmd member continues a prior solid model (no in-stream reset); only self-contained ppmd members are decoded".to_owned(),
        ));
    }
    let max_mb: u8 = read_byte(&mut hdr_pos)?;
    let esc_char: u8 = if max_order_raw & 0x40 != 0 {
        read_byte(&mut hdr_pos)?
    } else {
        2
    };

    let mut max_order: u32 = u32::from(max_order_raw & 0x1f) + 1;
    if max_order > 16 {
        max_order = 16 + (max_order - 16) * 3;
    }
    if max_order == 1 {
        return Err(Error::Decompression(
            "rar 2.9/3.x ppmd model order resolves to 1 (invalid)".to_owned(),
        ));
    }

    let mem_bytes: u32 = (u32::from(max_mb) + 1)
        .checked_shl(20)
        .ok_or_else(|| Error::Decompression("rar 2.9/3.x ppmd memory size overflow".to_owned()))?;

    let coder_stream: &[u8] = packed.get(hdr_pos..).ok_or_else(|| {
        Error::Decompression("rar 2.9/3.x ppmd stream truncated after header".to_owned())
    })?;

    let mut model: Ppmd7 = Ppmd7::new(max_order, mem_bytes);
    model.restart_model();
    let rc: RangeDec<'_> = RangeDec::new(coder_stream);

    let mut ctx: DecodeCtx<'_> = DecodeCtx {
        model,
        rc,
        char_mask: [0u8; 256],
        esc_count: 1,
        num_masked: 0,
    };

    let mut out: Vec<u8> = Vec::with_capacity(want);
    let mut guard: usize = 0;
    let max_iters: usize = want.saturating_mul(4).saturating_add(4096);
    while out.len() < want {
        guard += 1;
        if guard > max_iters {
            return Err(Error::Decompression(
                "rar 2.9/3.x ppmd decode exceeded iteration budget".to_owned(),
            ));
        }
        let ch: i32 = ctx.decode_char();
        if ch < 0 {
            return Err(Error::Decompression(format!(
                "rar 2.9/3.x ppmd decode produced {} of {want} bytes before a model error",
                out.len()
            )));
        }
        if ch == i32::from(esc_char) {
            let next: i32 = ctx.decode_char();
            match next {
                0 => {
                    return Err(Error::Decompression(
                        "rar 2.9/3.x ppmd member ends one block but declares more output; multi-block ppmd members are not decoded in-tree".to_owned(),
                    ));
                }
                -1 => {
                    return Err(Error::Decompression(
                        "rar 2.9/3.x ppmd escape sequence hit a model error".to_owned(),
                    ));
                }
                2 => break,
                3 => {
                    return Err(Error::Decompression(
                        "rar 2.9/3.x ppmd member carries a rarvm filter program (run as rarvm bytecode); the ppmd model is decoded in-tree but the rarvm interpreter is not".to_owned(),
                    ));
                }
                4 => {
                    let mut distance: u32 = 0;
                    let mut length: u32 = 0;
                    for i in 0..4 {
                        let b: i32 = ctx.decode_char();
                        if b < 0 {
                            return Err(Error::Decompression(
                                "rar 2.9/3.x ppmd lz-in-ppm escape truncated".to_owned(),
                            ));
                        }
                        if i == 3 {
                            length = b as u32;
                        } else {
                            distance = (distance << 8) + b as u32;
                        }
                    }
                    copy_string(&mut out, length + 32, distance + 2, want)?;
                    continue;
                }
                5 => {
                    let length: i32 = ctx.decode_char();
                    if length < 0 {
                        return Err(Error::Decompression(
                            "rar 2.9/3.x ppmd rle-in-ppm escape truncated".to_owned(),
                        ));
                    }
                    copy_string(&mut out, length as u32 + 4, 1, want)?;
                    continue;
                }
                _ => {
                    out.push(esc_char);
                    continue;
                }
            }
        }
        out.push(ch as u8);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn suballoc_index_tables_match_spec() {
        let sa: Suballoc = Suballoc::new(1 << 20);
        assert_eq!(sa.indx2units[0], 1);
        assert_eq!(sa.indx2units[1], 2);
        assert_eq!(sa.indx2units[2], 3);
        assert_eq!(sa.indx2units[3], 4);
        assert_eq!(sa.indx2units[4], 6);
        assert_eq!(sa.indx2units[PPMD_NUM_INDEXES - 1], 128);
        assert_eq!(sa.u2i(1), 0);
        assert_eq!(sa.u2i(128), PPMD_NUM_INDEXES - 1);
    }

    #[test]
    fn ns2indx_first_entries_match_spec() {
        let m: Ppmd7 = Ppmd7::new(16, 1 << 20);
        assert_eq!(m.ns2indx[0], 0);
        assert_eq!(m.ns2indx[1], 1);
        assert_eq!(m.ns2indx[2], 2);
        assert_eq!(m.ns2indx[3], 3);
        assert_eq!(m.ns2bsindx[0], 0);
        assert_eq!(m.ns2bsindx[1], 2);
        assert_eq!(m.ns2bsindx[2], 4);
        assert_eq!(m.ns2bsindx[11], 6);
        assert_eq!(m.hb2flag[0x3f], 0);
        assert_eq!(m.hb2flag[0x40], 8);
    }

    #[test]
    fn range_coder_desync_does_not_divide_by_zero() {
        let body: [u8; 211] = [
            127, 201, 162, 135, 188, 213, 100, 24, 160, 205, 10, 86, 26, 108, 16, 98, 130, 57, 207,
            240, 205, 60, 0, 50, 50, 160, 47, 69, 59, 49, 41, 155, 144, 131, 100, 62, 116, 6, 144,
            17, 145, 102, 184, 173, 2, 12, 206, 195, 160, 69, 49, 125, 51, 13, 159, 148, 199, 112,
            100, 152, 173, 118, 68, 174, 173, 160, 73, 19, 57, 243, 160, 11, 235, 12, 34, 250, 35,
            51, 131, 114, 56, 42, 212, 179, 12, 42, 222, 239, 10, 174, 181, 248, 5, 171, 108, 68,
            234, 19, 123, 33, 225, 76, 128, 155, 76, 218, 5, 179, 226, 71, 75, 23, 41, 179, 10,
            252, 113, 193, 134, 139, 92, 104, 4, 202, 87, 241, 160, 89, 199, 20, 166, 227, 204, 25,
            81, 99, 155, 126, 8, 58, 88, 22, 70, 146, 215, 128, 61, 193, 210, 131, 186, 19, 23, 37,
            15, 121, 213, 246, 167, 118, 108, 232, 193, 112, 210, 11, 57, 251, 88, 196, 167, 176,
            49, 225, 232, 37, 191, 188, 199, 184, 85, 189, 112, 64, 186, 209, 192, 111, 89, 145,
            90, 44, 84, 184, 35, 245, 208, 191, 90, 210, 125, 169, 120, 46, 78, 92, 42, 18, 144,
            237, 116,
        ];
        let _ = unpack3_ppmd(&body, 4096, 4 * 1024 * 1024);
    }
}
