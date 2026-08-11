use disrobe_pass_native::pseudo_c::VariableCollectionBenchmark;

fn main() {
    divan::main();
}

#[divan::bench(args = [16_u32, 1_024_u32, 4_096_u32])]
fn variable_collection_scale(bencher: divan::Bencher, count: u32) {
    let benchmark: VariableCollectionBenchmark = VariableCollectionBenchmark::new(count);
    let expected: usize = usize::try_from(count)
        .map_or(usize::MAX, |value: usize| value)
        .saturating_mul(2);
    assert_eq!(benchmark.collect(), Some(expected));
    bencher
        .counter(divan::counter::ItemsCount::new(u64::from(count) * 2))
        .bench_local(|| {
            let collected: Option<usize> = benchmark.collect();
            divan::black_box(collected)
        });
}
