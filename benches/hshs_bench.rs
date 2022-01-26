use criterion::BenchmarkId;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hshs::H;
//todo write better benchs
//https://bheisler.github.io/criterion.rs/book/criterion_rs.html
fn solve_bits10_benchmark(c: &mut Criterion) {
    c.bench_function("solve bits 10", |b| {
        b.iter(|| {
            let mut h = H::new(1, 10);
            h.solve(black_box(None))
        })
    });
}

fn solve_bits15_benchmark(c: &mut Criterion) {
    c.bench_function("solve bits 15", |b| {
        b.iter(|| {
            let mut h = H::new(1, 15);
            h.solve(black_box(None))
        })
    });
}

criterion_group!(benches, solve_bits15_benchmark);

criterion_main!(benches);
