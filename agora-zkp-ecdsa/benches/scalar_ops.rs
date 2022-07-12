use agora_zkp_ecdsa::arithmetic::{Modular, Scalar};
use agora_zkp_ecdsa::curve::Tom256k1;
use criterion::{criterion_group, criterion_main, Criterion};

use rand::rngs::OsRng;
use rand::Rng;

fn bench_scalar_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalar_ops");

    let mut rng = OsRng;
    let n = 50_usize;
    let random_scalars = vec![Scalar::<Tom256k1>::random(&mut rng); n];

    group.bench_function("inverse", |b| {
        let i = rng.gen_range(0..n);
        b.iter(|| random_scalars[i].inverse())
    });

    group.finish();
}

criterion_group!(benches, bench_scalar_ops);
criterion_main!(benches);
