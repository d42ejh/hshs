use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hshs::H;

fn solve_bits10_benchmark(c: &mut Criterion) {
    let mut h = H::new(1, 10);
    c.bench_function("bits 10", |b| b.iter(|| h.solve(black_box(&None))));
}
criterion_group!(benches, solve_bits10_benchmark);
criterion_main!(benches);
