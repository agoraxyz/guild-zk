use agora_zkp_ecdsa::arithmetic::{Point, Scalar};
use agora_zkp_ecdsa::curve::Tom256k1;
use criterion::{criterion_group, criterion_main, Criterion};

use rand::rngs::OsRng;
use rand::Rng;

fn bench_point_mul(c: &mut Criterion) {
    let mut group = c.benchmark_group("point_mul");

    let mut rng = OsRng;
    let generator_g = Point::<Tom256k1>::GENERATOR;
    let generator_h = &Point::<Tom256k1>::GENERATOR * Scalar::random(&mut rng);

    let n = 50_usize;
    let random_scalars = vec![Scalar::random(&mut rng); n];

    group.bench_function("single_mul", |b| {
        let i = rng.gen_range(0..n);
        b.iter(|| &generator_g * random_scalars[i])
    });

    group.bench_function("double_mul", |b| {
        let i = rng.gen_range(0..n);
        let j = rng.gen_range(0..n);
        b.iter(|| generator_g.double_mul(&random_scalars[i], &generator_h, &random_scalars[j]))
    });

    group.finish();
}

criterion_group!(benches, bench_point_mul);
criterion_main!(benches);
