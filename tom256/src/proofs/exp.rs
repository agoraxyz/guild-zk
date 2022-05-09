use crate::arithmetic::multimult::{MultiMult, Relation};
use crate::arithmetic::{Modular, Point, Scalar};
use crate::pedersen::*;
use crate::proofs::point_add::{PointAddCommitmentPoints, PointAddProof, PointAddSecrets};
use crate::utils::PointHasher;
use crate::{Curve, Cycle};

use std::ops::Neg;

use bigint::{Integer, U256};

use rand_core::{CryptoRng, RngCore};

pub enum ExpProofVariant<C: Curve, CC: Cycle<C>> {
    Odd {
        alpha: Scalar<C>,
        r: Scalar<C>,
        tx_r: Scalar<CC>,
        ty_r: Scalar<CC>,
    },
    Even {
        z: Scalar<C>,
        r: Scalar<C>,
        add_proof: PointAddProof<CC, C>,
        t1_x: Scalar<CC>,
        t1_y: Scalar<CC>,
    },
}

pub struct SingleExpProof<C: Curve, CC: Cycle<C>> {
    a: Point<C>,
    tx_p: Point<CC>,
    ty_p: Point<CC>,
    variant: ExpProofVariant<C, CC>,
}

#[derive(Clone)]
pub struct PointExpSecrets<C> {
    exp: Scalar<C>,
    point: Point<C>,
}

#[derive(Clone)]
pub struct PointExpCommitments<C, CC> {
    px: PedersenCommitment<CC>,
    py: PedersenCommitment<CC>,
    exp: PedersenCommitment<C>,
    q: Option<Point<C>>,
}

impl<C: Curve> PointExpSecrets<C> {
    // TODO: using `AffinePoint` this could be implied
    /// Ensures that the stored point is affine.
    pub fn new(exp: Scalar<C>, point: Point<C>) -> Self {
        Self {
            point: point.into_affine(),
            exp,
        }
    }

    pub fn commit<R, CC>(
        &self,
        rng: &mut R,
        base_pedersen_generator: &PedersenGenerator<C>,
        tom_pedersen_generator: &PedersenGenerator<CC>,
        q: Option<Point<C>>,
    ) -> PointExpCommitments<C, CC>
    where
        R: CryptoRng + RngCore,
        CC: Cycle<C>,
    {
        let q = if let Some(pt) = q {
            Some(pt.into_affine())
        } else {
            None
        };

        PointExpCommitments {
            px: tom_pedersen_generator.commit(rng, self.point.x().to_cycle_scalar()),
            py: tom_pedersen_generator.commit(rng, self.point.y().to_cycle_scalar()),
            exp: base_pedersen_generator.commit(rng, self.exp),
            q,
        }
    }
}

pub struct ExpProof<C: Curve, CC: Cycle<C>> {
    proofs: Vec<SingleExpProof<C, CC>>,
}

impl<CC: Cycle<C>, C: Curve> ExpProof<C, CC> {
    const HASH_ID: &'static [u8] = b"exp-proof";

    fn calculate_challenge(
        commitments: &PointExpCommitments<C, CC>,
        a_vec: &Vec<Point<C>>,
        tx_vec: &Vec<PedersenCommitment<CC>>,
        ty_vec: &Vec<PedersenCommitment<CC>>,
        security_param: usize,
    ) -> U256 {
        let mut point_hasher = PointHasher::new(Self::HASH_ID);
        point_hasher.insert_point(&commitments.px.clone().into_commitment());
        point_hasher.insert_point(&commitments.py.clone().into_commitment());

        for i in 0..security_param {
            point_hasher.insert_point(&a_vec[i].clone());
            point_hasher.insert_point(&tx_vec[i].clone().into_commitment());
            point_hasher.insert_point(&ty_vec[i].clone().into_commitment());
        }
        point_hasher.finalize()
    }

    pub fn construct<R: CryptoRng + RngCore>(
        rng: &mut R,
        base_pedersen_generator: &PedersenGenerator<C>,
        tom_pedersen_generator: &PedersenGenerator<CC>,
        secrets: &PointExpSecrets<C>,
        commitments: &PointExpCommitments<C, CC>,
        security_param: usize,
    ) -> Self {
        let mut alpha_vec: Vec<Scalar<C>> = Vec::with_capacity(security_param);
        let mut r_vec: Vec<Scalar<C>> = Vec::with_capacity(security_param);
        let mut t_vec: Vec<Point<C>> = Vec::with_capacity(security_param);
        let mut a_vec: Vec<Point<C>> = Vec::with_capacity(security_param);
        let mut tx_vec: Vec<PedersenCommitment<CC>> = Vec::with_capacity(security_param);
        let mut ty_vec: Vec<PedersenCommitment<CC>> = Vec::with_capacity(security_param);

        for i in 0..security_param {
            alpha_vec.push(Scalar::random(rng));
            r_vec.push(Scalar::random(rng));
            t_vec.push(Point::GENERATOR.scalar_mul(&alpha_vec[i]));
            a_vec.push(
                &t_vec[i]
                    + &base_pedersen_generator
                        .generator()
                        .clone()
                        .scalar_mul(&r_vec[i]),
            );

            let coord_t = &t_vec[i].clone().into_affine();
            if coord_t.is_identity() {
                // TODO: dont panic or smth
                panic!("intermediate value is identity");
            }

            tx_vec.push(tom_pedersen_generator.commit(rng, coord_t.x().to_cycle_scalar()));
            ty_vec.push(tom_pedersen_generator.commit(rng, coord_t.y().to_cycle_scalar()));
        }

        let mut challenge = Self::calculate_challenge(commitments, &a_vec, &tx_vec, &ty_vec, security_param);

        let mut all_exp_proofs = Vec::<SingleExpProof<C, CC>>::with_capacity(security_param);

        for i in 0..security_param {
            if challenge.is_odd().into() {
                all_exp_proofs.push(SingleExpProof {
                    a: a_vec[i].clone(),
                    tx_p: tx_vec[i].clone().into_commitment(),
                    ty_p: ty_vec[i].clone().into_commitment(),
                    variant: ExpProofVariant::Odd {
                        alpha: alpha_vec[i],
                        r: r_vec[i],
                        tx_r: tx_vec[i].randomness().clone(),
                        ty_r: ty_vec[i].randomness().clone(),
                    },
                });
            } else {
                let z = alpha_vec[i].sub(&secrets.exp);
                let mut t1 = Point::<C>::GENERATOR.scalar_mul(&z);
                if let Some(pt) = &commitments.q {
                    t1 = &t1 + &pt;
                }
                let coord_t1 = t1.clone().into_affine();
                if coord_t1.is_identity() {
                    // TODO: dont panic or smth
                    panic!("intermediate value is identity");
                }
                let t1_x = tom_pedersen_generator.commit(rng, coord_t1.x().to_cycle_scalar());
                let t1_y = tom_pedersen_generator.commit(rng, coord_t1.y().to_cycle_scalar());

                // Generate point add proof
                let add_secret =
                    PointAddSecrets::new(t1.clone(), secrets.point.clone(), t_vec[i].clone());
                let add_commitments = add_secret.commit(rng, &tom_pedersen_generator);
                let add_proof = PointAddProof::construct(
                    rng,
                    &tom_pedersen_generator,
                    &add_commitments,
                    &add_secret,
                );
                all_exp_proofs.push(SingleExpProof {
                    a: a_vec[i].clone(),
                    tx_p: tx_vec[i].clone().into_commitment(),
                    ty_p: ty_vec[i].clone().into_commitment(),
                    variant: ExpProofVariant::Even {
                        z,
                        r: r_vec[i] - (*commitments.exp.randomness()),
                        add_proof,
                        t1_x: *t1_x.randomness(),
                        t1_y: *t1_y.randomness(),
                    },
                });
            }
            challenge = challenge >> 1;
        }
        Self {
            proofs: all_exp_proofs,
        }
    }

    pub fn verify<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        base_pedersen_generator: &PedersenGenerator<C>,
        tom_pedersen_generator: &PedersenGenerator<CC>,
        commitments: &PointExpCommitments<C, CC>,
        security_param: usize,
    ) -> bool {
        if security_param > self.proofs.len() {
            // TODO: dont panic or smth
            //   maybe return false
            panic!("security level not achieved");
        }

        let mut tom_multimult = MultiMult::<CC>::new();
        let mut base_multimult = MultiMult::<C>::new();

        tom_multimult.add_known(Point::<CC>::GENERATOR);
        tom_multimult.add_known(tom_pedersen_generator.generator().clone());

        base_multimult.add_known(Point::<C>::GENERATOR);
        base_multimult.add_known(base_pedersen_generator.generator().clone());
        base_multimult.add_known(commitments.exp.clone().into_commitment());

        let mut point_hasher = PointHasher::new(Self::HASH_ID);
        point_hasher.insert_point(&commitments.px.clone().into_commitment());
        point_hasher.insert_point(&commitments.py.clone().into_commitment());

        for i in 0..security_param {
            point_hasher.insert_point(&self.proofs[i].a.clone());
            point_hasher.insert_point(&self.proofs[i].tx_p.clone());
            point_hasher.insert_point(&self.proofs[i].ty_p.clone());
        }
        let challenge = point_hasher.finalize();
        let indices = generate_indices(security_param, self.proofs.len(), rng);
        let challenge_bits = padded_bits(challenge, self.proofs.len());

        for j in 0..security_param {
            let i = indices[j];
            if challenge_bits[i] {
                if let ExpProofVariant::Odd {
                    alpha,
                    r,
                    tx_r,
                    ty_r,
                } = self.proofs[i].variant
                {
                    let t = Point::<C>::GENERATOR.scalar_mul(&alpha);
                    let mut relation_a = Relation::<C>::new();

                    relation_a.insert(t.clone(), Scalar::<C>::ONE);
                    relation_a.insert(base_pedersen_generator.generator().clone(), r);
                    relation_a.insert((&self.proofs[i].a).neg(), Scalar::<C>::ONE);

                    relation_a.drain(rng, &mut base_multimult);

                    let coord_t = t.clone().into_affine();
                    if coord_t.is_identity() {
                        // TODO: dont panic or smth
                        panic!("intermediate value is identity");
                    }

                    let sx = coord_t.x().to_cycle_scalar::<CC>();
                    let sy = coord_t.y().to_cycle_scalar::<CC>();

                    let mut relation_tx = Relation::new();
                    let mut relation_ty = Relation::new();

                    relation_tx.insert(Point::<CC>::GENERATOR, sx);
                    relation_tx.insert(tom_pedersen_generator.generator().clone(), tx_r);
                    relation_tx.insert((&self.proofs[i].tx_p).neg(), Scalar::<CC>::ONE);

                    relation_ty.insert(Point::<CC>::GENERATOR, sy);
                    relation_ty.insert(tom_pedersen_generator.generator().clone(), ty_r);
                    relation_ty.insert((&self.proofs[i].ty_p).neg(), Scalar::<CC>::ONE);

                    relation_tx.drain(rng, &mut tom_multimult);
                    relation_ty.drain(rng, &mut tom_multimult);
                } else {
                    panic!("this should never be invoked");
                }
            } else {
                if let ExpProofVariant::Even {
                    z,
                    r,
                    add_proof,
                    t1_x,
                    t1_y,
                } = &self.proofs[i].variant
                {
                    let mut t = Point::<C>::GENERATOR.scalar_mul(&z);

                    let mut relation_a = Relation::<C>::new();
                    relation_a.insert(t.clone(), Scalar::<C>::ONE);
                    relation_a.insert(commitments.exp.clone().into_commitment(), Scalar::<C>::ONE);
                    relation_a.insert(self.proofs[i].a.clone(), Scalar::<C>::ONE);
                    relation_a.insert(base_pedersen_generator.generator().clone(), *r);

                    if let Some(q) = &commitments.q {
                        t = &t + q;
                    }

                    let coord_t = t.clone().into_affine();
                    if coord_t.is_identity() {
                        // TODO: dont panic or smth
                        panic!("intermediate value is identity");
                    }

                    let sx = coord_t.x().to_cycle_scalar::<CC>();
                    let sy = coord_t.y().to_cycle_scalar::<CC>();

                    let t1_x = Point::<CC>::GENERATOR.double_mul(
                        &sx,
                        &tom_pedersen_generator.generator().clone(),
                        t1_x,
                    );
                    let t1_y = Point::<CC>::GENERATOR.double_mul(
                        &sy,
                        &tom_pedersen_generator.generator().clone(),
                        t1_y,
                    );

                    let point_add_commitments = PointAddCommitmentPoints::new(
                        t1_x,
                        t1_y,
                        commitments.px.clone().into_commitment(),
                        commitments.py.clone().into_commitment(),
                        self.proofs[i].tx_p.clone(),
                        self.proofs[i].ty_p.clone(),
                    );

                    add_proof.aggregate(
                        rng,
                        tom_pedersen_generator,
                        &point_add_commitments,
                        &mut tom_multimult,
                    );
                } else {
                    panic!("this should never be invoked");
                }
            }
        }

        tom_multimult.evaluate().is_identity()
            && base_multimult.evaluate().is_identity()
    }
}

fn padded_bits(number: U256, length: usize) -> Vec<bool> {
    let mut ret = Vec::<bool>::with_capacity(length);

    let mut current_idx = 0;
    for limb in number.limbs() {
        let mut limb = limb.0;
        for _ in 0..64 {
            ret.push(limb % 2 == 1);
            limb = limb >> 1;
            current_idx += 1;

            if current_idx >= length {
                return ret;
            }
        }
    }

    ret.truncate(length);
    ret
}

fn generate_indices<R: CryptoRng + RngCore>(
    idx_num: usize,
    limit: usize,
    rng: &mut R,
) -> Vec<usize> {
    let mut ret = Vec::<usize>::with_capacity(limit);

    for i in (0..limit).rev() {
        ret.push(i);
    }

    for i in 0..limit - 2 {
        let random_idx = rng.next_u64() as usize % (limit - i) + i;
        let k = ret[i];
        ret[i] = ret[random_idx];
        ret[random_idx] = k;
    }

    ret.truncate(idx_num);
    ret
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{Secp256k1, Tom256k1};
    use rand::rngs::StdRng;
    use rand_core::SeedableRng;

    #[test]
    fn padded_bits_valid() {
        let test_u256 = U256::from_u32(1);
        assert_eq!(padded_bits(test_u256, 1), [true]);
        assert_eq!(padded_bits(test_u256, 4), [true, false, false, false]);

        let test_u256 = U256::from_u32(2);
        assert_eq!(padded_bits(test_u256, 1), [false]);
        assert_eq!(padded_bits(test_u256, 2), [false, true]);

        let test_u256 =
            U256::from_be_hex("000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFF");
        let true_64 = vec![true; 64];
        assert_eq!(padded_bits(test_u256, 64), true_64);
        assert_eq!(padded_bits(test_u256, 65), [true_64, vec![false]].concat());
    }

    #[test]
    fn generate_indices_valid() {
        let idx_num = 5;
        let limit = 5;
        let mut rng = StdRng::from_seed([1; 32]);

        for _ in 0..10 {
            println!("{:?}", generate_indices(idx_num, limit, &mut rng));
        }
    }

    #[test]
    fn exp_proof_valid() {
        let mut rng = StdRng::from_seed([1; 32]);
        let base_pedersen_generator = PedersenGenerator::<Secp256k1>::new(&mut rng);
        let tom_pedersen_generator = PedersenGenerator::<Tom256k1>::new(&mut rng);

        let exponent = Scalar::<Secp256k1>::ONE;
        let result = Point::<Secp256k1>::GENERATOR.scalar_mul(&exponent);

        let secrets = PointExpSecrets::new(exponent, result);
        let commitments = secrets.commit(
            &mut rng,
            &base_pedersen_generator,
            &tom_pedersen_generator,
            None,
        );

        let security_param = 10;
        let exp_proof = ExpProof::construct(
            &mut rng,
            &base_pedersen_generator,
            &tom_pedersen_generator,
            &secrets,
            &commitments,
            security_param,
        );

        assert!(exp_proof.verify(
            &mut rng,
            &base_pedersen_generator,
            &tom_pedersen_generator,
            &commitments,
            security_param
        ));
    }
}
