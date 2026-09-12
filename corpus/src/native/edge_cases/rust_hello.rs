fn compute(n: u32) -> u64 {
    (1..=n).map(|i: u32| u64::from(i) * u64::from(i)).sum()
}

fn main() {
    let total: u64 = compute(10);
    println!("{total}");
}
