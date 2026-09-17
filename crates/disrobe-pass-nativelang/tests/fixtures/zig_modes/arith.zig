export fn dr_mix(a: u64, b: u64) u64 {
    return a *% 3 +% b *% 5;
}

export fn dr_gcd(a0: u64, b0: u64) u64 {
    var a: u64 = a0;
    var b: u64 = b0;
    while (b != 0) {
        const t: u64 = b;
        b = a % b;
        a = t;
    }
    return a;
}

export fn dr_clamp(v: i64, lo: i64, hi: i64) i64 {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

export fn dr_popcount(x: u64) u64 {
    return @popCount(x);
}

export fn dr_rotl(x: u64, n: u64) u64 {
    const s: u6 = @truncate(n);
    if (s == 0) return x;
    return (x << s) | (x >> @as(u6, @intCast(64 - @as(u7, s))));
}

export fn dr_sum_to(n: u64) u64 {
    var acc: u64 = 0;
    var i: u64 = 0;
    while (i <= n) : (i +%= 1) {
        acc +%= i;
    }
    return acc;
}

export fn dr_select(flag: u64, a: u64, b: u64) u64 {
    return if (flag != 0) a else b;
}

export fn dr_abs_diff(a: i64, b: i64) i64 {
    return if (a > b) a -% b else b -% a;
}

pub fn main() u8 {
    const total: u64 = dr_mix(3, 4) +% dr_gcd(12, 18) +% dr_popcount(255) +%
        dr_rotl(1, 3) +% dr_sum_to(10) +% dr_select(1, 7, 9);
    const signed: i64 = dr_abs_diff(3, 9) +% dr_clamp(7, 1, 5);
    return @truncate(total +% @as(u64, @bitCast(signed)));
}
