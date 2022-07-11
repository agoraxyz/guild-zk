use agora_zkp_ecdsa::arithmetic::{Point, Scalar};
use agora_zkp_ecdsa::curve::{Secp256k1, Tom256k1};
use agora_zkp_ecdsa::pedersen::PedersenCycle;
use agora_zkp_ecdsa::proofs::{ExpProof, ExpSecrets};

use rand_core::OsRng;

fn main() {
    let mut rng = OsRng;
    let base_gen = Point::<Secp256k1>::GENERATOR;
    let pedersen_cycle = PedersenCycle::<Secp256k1, Tom256k1>::new(&mut rng);

    let exponent = Scalar::<Secp256k1>::random(&mut rng);
    let result = base_gen.scalar_mul(&exponent);

    let secrets = ExpSecrets::new(exponent, result.into());
    let commitments = secrets.commit(&mut rng, &pedersen_cycle);

    let security_param = 60;
    let proof = ExpProof::construct(
        &mut rng,
        &base_gen,
        &pedersen_cycle,
        &secrets,
        &commitments,
        security_param,
        None,
    )
    .unwrap();

    assert!(proof
        .verify(
            &mut rng,
            &base_gen,
            &pedersen_cycle,
            &commitments.into_commitments(),
            security_param,
            None,
        )
        .is_ok());
}
