use crate::arithmetic::multimult::{MultiMult, Relation};
use crate::arithmetic::{Modular, Point, Scalar};
use crate::curve::Curve;
use crate::hasher::PointHasher;
use crate::pedersen::*;
use crate::rng::CryptoCoreRng;

use borsh::{BorshDeserialize, BorshSerialize};

use std::ops::Neg;

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct MultiplicationProof<C: Curve> {
    c4: Point<C>,
    commitment_to_random_1: Point<C>,
    commitment_to_random_2: Point<C>,
    commitment_to_random_3: Point<C>,
    a4_1: Point<C>,
    a4_2: Point<C>,
    mask_x: Scalar<C>,
    mask_y: Scalar<C>,
    mask_z: Scalar<C>,
    mask_random_x: Scalar<C>,
    mask_random_y: Scalar<C>,
    mask_random_z: Scalar<C>,
    mask_r4: Scalar<C>,
}

impl<C: Curve> MultiplicationProof<C> {
    const HASH_ID: &'static [u8] = b"multiplication-proof";

    #[allow(clippy::too_many_arguments)]
    pub fn construct<R: CryptoCoreRng>(
        rng: &mut R,
        pedersen_generator: &PedersenGenerator<C>,
        commitment_to_x: &PedersenCommitment<C>,
        commitment_to_y: &PedersenCommitment<C>,
        commitment_to_z: &PedersenCommitment<C>,
        x: Scalar<C>,
        y: Scalar<C>,
        z: Scalar<C>,
    ) -> Self {
        let c4 = commitment_to_y.commitment() * x;
        let r4 = commitment_to_y.randomness() * &x;

        let random_scalar_1 = Scalar::random(rng);
        let random_scalar_2 = Scalar::random(rng);
        let random_scalar_3 = Scalar::random(rng);

        let commitment_to_random_1 = pedersen_generator.commit(rng, random_scalar_1);
        let commitment_to_random_2 = pedersen_generator.commit(rng, random_scalar_2);
        let commitment_to_random_3 = pedersen_generator.commit(rng, random_scalar_3);

        let a4_1 = pedersen_generator.commit(rng, random_scalar_3);
        let a4_2 = commitment_to_y.commitment() * random_scalar_1;

        let mut hasher = PointHasher::new(Self::HASH_ID);
        hasher.insert_points(&[
            commitment_to_x.commitment(),
            commitment_to_y.commitment(),
            commitment_to_z.commitment(),
            &c4,
            commitment_to_random_1.commitment(),
            commitment_to_random_2.commitment(),
            commitment_to_random_3.commitment(),
            a4_1.commitment(),
            &a4_2,
        ]);
        let challenge = hasher.finalize();
        let challenge_scalar = Scalar::new(challenge);

        let mask_x = random_scalar_1 - challenge_scalar * x;
        let mask_y = random_scalar_2 - challenge_scalar * y;
        let mask_z = random_scalar_3 - challenge_scalar * z;

        let mask_random_x = commitment_to_random_1
            .randomness()
            .sub(&(&challenge_scalar * commitment_to_x.randomness()));
        let mask_random_y = commitment_to_random_2
            .randomness()
            .sub(&(&challenge_scalar * commitment_to_y.randomness()));
        let mask_random_z = commitment_to_random_3
            .randomness()
            .sub(&(&challenge_scalar * commitment_to_z.randomness()));
        let mask_r4 = a4_1.randomness().sub(&(challenge_scalar * r4));

        Self {
            c4,
            commitment_to_random_1: commitment_to_random_1.into_commitment(),
            commitment_to_random_2: commitment_to_random_2.into_commitment(),
            commitment_to_random_3: commitment_to_random_3.into_commitment(),
            a4_1: a4_1.into_commitment(),
            a4_2,
            mask_x,
            mask_y,
            mask_z,
            mask_random_x,
            mask_random_y,
            mask_random_z,
            mask_r4,
        }
    }

    pub fn aggregate<R: CryptoCoreRng>(
        &self,
        rng: &mut R,
        pedersen_generator: &PedersenGenerator<C>,
        commitment_to_x: &Point<C>,
        commitment_to_y: &Point<C>,
        commitment_to_z: &Point<C>,
        multimult: &mut MultiMult<C>,
    ) {
        let mut hasher = PointHasher::new(Self::HASH_ID);
        hasher.insert_points(&[
            commitment_to_x,
            commitment_to_y,
            commitment_to_z,
            &self.c4,
            &self.commitment_to_random_1,
            &self.commitment_to_random_2,
            &self.commitment_to_random_3,
            &self.a4_1,
            &self.a4_2,
        ]);
        let challenge = hasher.finalize();
        let challenge_scalar = Scalar::new(challenge);

        let mut relation_x = Relation::new();
        let mut relation_y = Relation::new();
        let mut relation_z = Relation::new();
        let mut relation_a4_1 = Relation::<C>::new();
        let mut relation_a4_2 = Relation::<C>::new();

        relation_x.insert(Point::<C>::GENERATOR, self.mask_x);
        relation_x.insert(pedersen_generator.generator().clone(), self.mask_random_x);
        relation_x.insert(commitment_to_x.clone(), challenge_scalar);
        relation_x.insert((&self.commitment_to_random_1).neg(), Scalar::<C>::ONE);

        relation_y.insert(Point::<C>::GENERATOR, self.mask_y);
        relation_y.insert(pedersen_generator.generator().clone(), self.mask_random_y);
        relation_y.insert(commitment_to_y.clone(), challenge_scalar);
        relation_y.insert((&self.commitment_to_random_2).neg(), Scalar::<C>::ONE);

        relation_z.insert(Point::<C>::GENERATOR, self.mask_z);
        relation_z.insert(pedersen_generator.generator().clone(), self.mask_random_z);
        relation_z.insert(commitment_to_z.clone(), challenge_scalar);
        relation_z.insert((&self.commitment_to_random_3).neg(), Scalar::<C>::ONE);

        relation_a4_1.insert(Point::<C>::GENERATOR, self.mask_z);
        relation_a4_1.insert(pedersen_generator.generator().clone(), self.mask_r4);
        relation_a4_1.insert(self.c4.clone(), challenge_scalar);
        relation_a4_1.insert((&self.a4_1).neg(), Scalar::<C>::ONE);

        relation_a4_2.insert(commitment_to_y.clone(), self.mask_x);
        relation_a4_2.insert(self.c4.clone(), challenge_scalar);
        relation_a4_2.insert((&self.a4_2).neg(), Scalar::<C>::ONE);

        relation_x.drain(rng, multimult);
        relation_y.drain(rng, multimult);
        relation_z.drain(rng, multimult);
        relation_a4_1.drain(rng, multimult);
        relation_a4_2.drain(rng, multimult);
    }

    #[cfg(test)]
    pub fn verify<R: CryptoCoreRng>(
        &self,
        rng: &mut R,
        pedersen_generator: &PedersenGenerator<C>,
        commitment_to_x: &Point<C>,
        commitment_to_y: &Point<C>,
        commitment_to_z: &Point<C>,
    ) -> bool {
        let mut multimult = MultiMult::new();
        self.aggregate(
            rng,
            pedersen_generator,
            commitment_to_x,
            commitment_to_y,
            commitment_to_z,
            &mut multimult,
        );
        multimult.evaluate().is_identity()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::curve::Tom256k1;
    use rand::rngs::StdRng;
    use rand_core::SeedableRng;

    #[test]
    fn valid_multiplication_proof() {
        let mut rng = StdRng::from_seed([1; 32]);
        let x = Scalar::<Tom256k1>::random(&mut rng);
        let y = Scalar::<Tom256k1>::random(&mut rng);
        let z = x * y;
        let pedersen_generator = PedersenGenerator::new(&mut rng);
        let commitment_x = pedersen_generator.commit(&mut rng, x);
        let commitment_y = pedersen_generator.commit(&mut rng, y);
        let commitment_z = pedersen_generator.commit(&mut rng, z);

        let multiplication_proof = MultiplicationProof::construct(
            &mut rng,
            &pedersen_generator,
            &commitment_x,
            &commitment_y,
            &commitment_z,
            x,
            y,
            z,
        );

        assert!(multiplication_proof.verify(
            &mut rng,
            &pedersen_generator,
            commitment_x.commitment(),
            commitment_y.commitment(),
            commitment_z.commitment(),
        ));
    }

    #[test]
    fn invalid_multiplication_proof() {
        let mut rng = StdRng::from_seed([1; 32]);
        let x = Scalar::<Tom256k1>::random(&mut rng);
        let y = Scalar::<Tom256k1>::random(&mut rng);
        let z = x * y;
        let pedersen_generator = PedersenGenerator::new(&mut rng);
        let commitment_x = pedersen_generator.commit(&mut rng, x);
        let commitment_y = pedersen_generator.commit(&mut rng, y);
        let commitment_z = pedersen_generator.commit(&mut rng, z);

        let multiplication_proof = MultiplicationProof::construct(
            &mut rng,
            &pedersen_generator,
            &commitment_x,
            &commitment_y,
            &commitment_z,
            x,
            y,
            z,
        );

        let invalid_pedersen_generator = PedersenGenerator::new(&mut rng);
        assert!(!multiplication_proof.verify(
            &mut rng,
            &invalid_pedersen_generator,
            commitment_x.commitment(),
            commitment_y.commitment(),
            commitment_z.commitment(),
        ));

        let invalid_x = Scalar::<Tom256k1>::random(&mut rng);
        let invalid_commitment_x = pedersen_generator.commit(&mut rng, invalid_x);

        assert!(!multiplication_proof.verify(
            &mut rng,
            &pedersen_generator,
            invalid_commitment_x.commitment(),
            commitment_y.commitment(),
            commitment_z.commitment(),
        ));

        let invalid_y = Scalar::<Tom256k1>::random(&mut rng);
        let invalid_commitment_y = pedersen_generator.commit(&mut rng, invalid_y);

        assert!(!multiplication_proof.verify(
            &mut rng,
            &pedersen_generator,
            commitment_x.commitment(),
            invalid_commitment_y.commitment(),
            commitment_z.commitment(),
        ));

        let invalid_z = z + Scalar::ONE;
        let invalid_commitment_z = pedersen_generator.commit(&mut rng, invalid_z);

        assert!(!multiplication_proof.verify(
            &mut rng,
            &pedersen_generator,
            commitment_x.commitment(),
            commitment_y.commitment(),
            invalid_commitment_z.commitment(),
        ));
    }
}
