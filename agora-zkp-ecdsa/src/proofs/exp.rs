use crate::arithmetic::multimult::{MultiMult, Relation};
use crate::arithmetic::AffinePoint;
use crate::arithmetic::{Point, Scalar};
use crate::curve::{Curve, Cycle};
use crate::hasher::PointHasher;
use crate::pedersen::*;
use crate::proofs::point_add::{PointAddCommitmentPoints, PointAddProof, PointAddSecrets};
use crate::rng::CryptoCoreRng;

use bigint::{Encoding, Integer, U256};
use borsh::{BorshDeserialize, BorshSerialize};

use std::ops::Neg;

#[allow(clippy::large_enum_variant)]
#[derive(BorshDeserialize, BorshSerialize)]
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
        t1_x: Scalar<CC>,
        t1_y: Scalar<CC>,
        add_proof: PointAddProof<CC, C>,
    },
}

#[derive(BorshDeserialize, BorshSerialize)]
pub struct SingleExpProof<C: Curve, CC: Cycle<C>> {
    a: Point<C>,
    tx_p: Point<CC>,
    ty_p: Point<CC>,
    variant: ExpProofVariant<C, CC>,
}

#[derive(Clone)]
pub struct ExpSecrets<C: Curve> {
    point: AffinePoint<C>,
    exp: Scalar<C>,
}

#[derive(Clone)]
pub struct ExpCommitments<C: Curve, CC: Cycle<C>> {
    pub(super) px: PedersenCommitment<CC>,
    pub(super) py: PedersenCommitment<CC>,
    pub(super) exp: PedersenCommitment<C>,
}

#[derive(Clone, BorshDeserialize, BorshSerialize)]
pub struct ExpCommitmentPoints<C: Curve, CC: Cycle<C>> {
    pub(super) px: Point<CC>,
    pub(super) py: Point<CC>,
    pub(super) exp: Point<C>,
}

impl<C: Curve> ExpSecrets<C> {
    pub fn new(exp: Scalar<C>, point: AffinePoint<C>) -> Self {
        Self { exp, point }
    }

    pub fn commit<R, CC>(
        &self,
        rng: &mut R,
        pedersen: &PedersenCycle<C, CC>,
    ) -> ExpCommitments<C, CC>
    where
        R: CryptoCoreRng,
        CC: Cycle<C>,
    {
        ExpCommitments {
            px: pedersen
                .cycle()
                .commit(rng, self.point.x().to_cycle_scalar()),
            py: pedersen
                .cycle()
                .commit(rng, self.point.y().to_cycle_scalar()),
            exp: pedersen.base().commit(rng, self.exp),
        }
    }
}

impl<C: Curve, CC: Cycle<C>> ExpCommitments<C, CC> {
    pub fn into_commitments(self) -> ExpCommitmentPoints<C, CC> {
        ExpCommitmentPoints {
            px: self.px.into_commitment(),
            py: self.py.into_commitment(),
            exp: self.exp.into_commitment(),
        }
    }
}

impl<C: Curve, CC: Cycle<C>> ExpCommitmentPoints<C, CC> {
    pub fn new(exp: Point<C>, px: Point<CC>, py: Point<CC>) -> Self {
        Self { exp, px, py }
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
pub struct ExpProof<C: Curve, CC: Cycle<C>> {
    proofs: Vec<SingleExpProof<C, CC>>,
}

impl<CC: Cycle<C>, C: Curve> ExpProof<C, CC> {
    const HASH_ID: &'static [u8] = b"exp-proof";

    pub fn construct<R: CryptoCoreRng>(
        rng: &mut R,
        base_gen: &Point<C>,
        pedersen: &PedersenCycle<C, CC>,
        secrets: &ExpSecrets<C>,
        commitments: &ExpCommitments<C, CC>,
        security_param: usize,
        q_point: Option<Point<C>>,
    ) -> Result<Self, String> {
        let mut alpha_vec = Vec::<Scalar<C>>::with_capacity(security_param);
        let mut r_vec = Vec::<Scalar<C>>::with_capacity(security_param);
        let mut t_vec = Vec::<Point<C>>::with_capacity(security_param);
        let mut a_vec = Vec::<Point<C>>::with_capacity(security_param);
        let mut tx_vec = Vec::<PedersenCommitment<CC>>::with_capacity(security_param);
        let mut ty_vec = Vec::<PedersenCommitment<CC>>::with_capacity(security_param);

        let mut point_hasher = PointHasher::new(Self::HASH_ID);
        point_hasher.insert_point(commitments.px.commitment());
        point_hasher.insert_point(commitments.py.commitment());

        for i in 0..security_param {
            // exponent
            alpha_vec.push(Scalar::random(rng));
            // random r scalars
            r_vec.push(Scalar::random(rng));
            // T = g^alpha
            t_vec.push(base_gen * alpha_vec[i]);
            // A = g^alpha + h^r (essentially a commitment in the base curve)
            a_vec.push(&t_vec[i] + &(pedersen.base().generator() * r_vec[i]));

            let coord_t = t_vec[i].to_affine();
            if coord_t.is_identity() {
                return Err("intermediate value is identity".to_owned());
            }
            // commitment to Tx
            tx_vec.push(pedersen.cycle().commit(rng, coord_t.x().to_cycle_scalar()));
            // commitment to Ty
            ty_vec.push(pedersen.cycle().commit(rng, coord_t.y().to_cycle_scalar()));

            // update hasher with current points
            point_hasher.insert_point(&a_vec[i]);
            point_hasher.insert_point(tx_vec[i].commitment());
            point_hasher.insert_point(ty_vec[i].commitment());
        }

        let mut challenge = point_hasher.finalize();
        let mut all_exp_proofs = Vec::<SingleExpProof<C, CC>>::with_capacity(security_param);

        for (alpha, (a, (r, (t, (tx, ty))))) in alpha_vec.into_iter().zip(
            a_vec.into_iter().zip(
                r_vec.into_iter().zip(
                    t_vec
                        .into_iter()
                        .zip(tx_vec.into_iter().zip(ty_vec.into_iter())),
                ),
            ),
        ) {
            if challenge.is_odd().into() {
                let tx_r = *tx.randomness();
                let ty_r = *ty.randomness();
                all_exp_proofs.push(SingleExpProof {
                    a,
                    tx_p: tx.into_commitment(),
                    ty_p: ty.into_commitment(),
                    variant: ExpProofVariant::Odd {
                        alpha,
                        r,
                        tx_r,
                        ty_r,
                    },
                });
            } else {
                let z = alpha - secrets.exp;
                let mut t1 = base_gen * z;
                if let Some(pt) = q_point.as_ref() {
                    t1 += pt;
                }

                if t1.is_identity() {
                    return Err("intermediate value is identity".to_owned());
                }

                // Generate point add proof
                let add_secret = PointAddSecrets::new(t1.into(), secrets.point.clone(), t.into());
                // NOTE only commits t1 and uses existing commitments for the rest
                let add_commitments = add_secret.commit_p_only(
                    rng,
                    pedersen.cycle(),
                    commitments.px.clone(),
                    commitments.py.clone(),
                    tx.clone(),
                    ty.clone(),
                );
                let add_proof =
                    PointAddProof::construct(rng, pedersen.cycle(), &add_commitments, &add_secret);

                all_exp_proofs.push(SingleExpProof {
                    a,
                    tx_p: tx.into_commitment(),
                    ty_p: ty.into_commitment(),
                    variant: ExpProofVariant::Even {
                        z,
                        r: r - (*commitments.exp.randomness()),
                        t1_x: *add_commitments.px.randomness(),
                        t1_y: *add_commitments.py.randomness(),
                        add_proof,
                    },
                });
            }

            challenge >>= 1;
        }
        Ok(Self {
            proofs: all_exp_proofs,
        })
    }

    pub fn verify<R: CryptoCoreRng>(
        &self,
        rng: &mut R,
        base_gen: &Point<C>,
        pedersen: &PedersenCycle<C, CC>,
        commitments: &ExpCommitmentPoints<C, CC>,
        security_param: usize,
        q_point: Option<Point<C>>,
    ) -> Result<(), String> {
        if security_param > self.proofs.len() {
            return Err("security level not achieved".to_owned());
        }

        let mut tom_multimult = MultiMult::<CC>::new();
        let mut base_multimult = MultiMult::<C>::new();

        tom_multimult.add_known(Point::<CC>::GENERATOR);
        tom_multimult.add_known(pedersen.cycle().generator().clone());

        base_multimult.add_known(base_gen.clone());
        base_multimult.add_known(pedersen.base().generator().clone());
        base_multimult.add_known(commitments.exp.clone());

        let mut point_hasher = PointHasher::new(Self::HASH_ID);
        point_hasher.insert_point(&commitments.px);
        point_hasher.insert_point(&commitments.py);

        for i in 0..security_param {
            point_hasher.insert_point(&self.proofs[i].a);
            point_hasher.insert_point(&self.proofs[i].tx_p);
            point_hasher.insert_point(&self.proofs[i].ty_p);
        }
        let challenge = point_hasher.finalize();

        let indices = generate_indices(security_param, self.proofs.len(), rng);
        let challenge_bits = padded_bits(challenge, self.proofs.len());

        for i in indices.into_iter() {
            match &self.proofs[i].variant {
                ExpProofVariant::Odd {
                    alpha,
                    r,
                    tx_r,
                    ty_r,
                } => {
                    if !challenge_bits[i] {
                        return Err("challenge hash mismatch".to_owned());
                    }

                    let t = base_gen.scalar_mul(alpha);
                    let mut relation_a = Relation::<C>::new();

                    relation_a.insert(t.clone(), Scalar::<C>::ONE);
                    relation_a.insert(pedersen.base().generator().clone(), *r);
                    relation_a.insert((&self.proofs[i].a).neg(), Scalar::<C>::ONE);

                    relation_a.drain(rng, &mut base_multimult);

                    let coord_t: AffinePoint<C> = t.into();
                    if coord_t.is_identity() {
                        return Err("intermediate value is identity".to_owned());
                    }

                    let sx = coord_t.x().to_cycle_scalar::<CC>();
                    let sy = coord_t.y().to_cycle_scalar::<CC>();

                    let mut relation_tx = Relation::new();
                    let mut relation_ty = Relation::new();

                    relation_tx.insert(Point::<CC>::GENERATOR, sx);
                    relation_tx.insert(pedersen.cycle().generator().clone(), *tx_r);
                    relation_tx.insert((&self.proofs[i].tx_p).neg(), Scalar::<CC>::ONE);

                    relation_ty.insert(Point::<CC>::GENERATOR, sy);
                    relation_ty.insert(pedersen.cycle().generator().clone(), *ty_r);
                    relation_ty.insert((&self.proofs[i].ty_p).neg(), Scalar::<CC>::ONE);

                    relation_tx.drain(rng, &mut tom_multimult);
                    relation_ty.drain(rng, &mut tom_multimult);
                }
                ExpProofVariant::Even {
                    z,
                    r,
                    add_proof,
                    t1_x,
                    t1_y,
                } => {
                    if challenge_bits[i] {
                        return Err("challenge hash mismatch".to_owned());
                    }

                    let mut t = base_gen.scalar_mul(z);

                    let mut relation_a = Relation::<C>::new();
                    relation_a.insert(t.clone(), Scalar::<C>::ONE);
                    relation_a.insert(commitments.exp.clone(), Scalar::<C>::ONE);
                    relation_a.insert((&self.proofs[i].a).neg(), Scalar::<C>::ONE);
                    relation_a.insert(pedersen.base().generator().clone(), *r);

                    relation_a.drain(rng, &mut base_multimult);

                    if let Some(pt) = q_point.as_ref() {
                        t += pt;
                    }

                    let coord_t: AffinePoint<C> = t.clone().into();
                    if coord_t.is_identity() {
                        return Err("intermediate value is identity".to_owned());
                    }

                    let sx = coord_t.x().to_cycle_scalar::<CC>();
                    let sy = coord_t.y().to_cycle_scalar::<CC>();

                    let t1_com_x = pedersen.cycle().commit_with_randomness(sx, *t1_x);
                    let t1_com_y = pedersen.cycle().commit_with_randomness(sy, *t1_y);

                    let point_add_commitments = PointAddCommitmentPoints::new(
                        t1_com_x.into_commitment(),
                        t1_com_y.into_commitment(),
                        commitments.px.clone(),
                        commitments.py.clone(),
                        self.proofs[i].tx_p.clone(),
                        self.proofs[i].ty_p.clone(),
                    );

                    add_proof.aggregate(
                        rng,
                        pedersen.cycle(),
                        &point_add_commitments,
                        &mut tom_multimult,
                    );
                }
            }
        }

        let tom_res = tom_multimult.evaluate();
        let base_res = base_multimult.evaluate();

        if !(tom_res.is_identity() && base_res.is_identity()) {
            return Err("proof is invalid".to_owned());
        }
        Ok(())
    }
}

fn padded_bits(number: U256, length: usize) -> Vec<bool> {
    let mut ret = Vec::<bool>::with_capacity(length);

    let number_bytes = number.to_le_bytes();

    let mut current_idx = 0;
    for byte in number_bytes {
        let mut byte_copy = byte;
        for _ in 0..8 {
            ret.push(byte_copy % 2 == 1);
            byte_copy >>= 1;
            current_idx += 1;

            if current_idx >= length {
                return ret;
            }
        }
    }

    ret.truncate(length);
    ret
}

// Get random number from interval [min, max]
fn get_rand_range<R: CryptoCoreRng>(min: usize, max: usize, rng: &mut R) -> usize {
    rng.next_u64() as usize % (max - min + 1) + min
}

fn generate_indices<R: CryptoCoreRng>(idx_num: usize, limit: usize, rng: &mut R) -> Vec<usize> {
    let mut ret = Vec::<usize>::with_capacity(limit);

    for i in 0..limit {
        ret.push(i);
    }

    let mut randoms = vec![];
    for i in 0..limit - 2 {
        let random_idx = get_rand_range(i, limit - 1, rng);
        randoms.push(random_idx);
        ret.swap(i, random_idx);
    }

    ret.truncate(idx_num);
    ret
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::curve::{Secp256k1, Tom256k1};
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
    fn rand_range_valid() {
        let max = 217;
        let min = 214;
        let mut rng = StdRng::from_seed([1; 32]);
        for _ in 0..1000 {
            let rand = get_rand_range(min, max, &mut rng);
            assert!(rand <= max);
            assert!(rand >= min);
        }
    }

    #[test]
    fn exp_proof_valid_without_q() {
        let mut rng = StdRng::from_seed([2; 32]);
        let base_gen = Point::<Secp256k1>::GENERATOR;
        let pedersen = PedersenCycle::<Secp256k1, Tom256k1>::new(&mut rng);

        let exponent = Scalar::<Secp256k1>::random(&mut rng);
        let result = Point::<Secp256k1>::GENERATOR.scalar_mul(&exponent);

        let secrets = ExpSecrets::new(exponent, result.into());
        let commitments = secrets.commit(&mut rng, &pedersen);

        let security_param = 10;
        let exp_proof = ExpProof::construct(
            &mut rng,
            &base_gen,
            &pedersen,
            &secrets,
            &commitments,
            security_param,
            None,
        )
        .unwrap();

        assert!(exp_proof
            .verify(
                &mut rng,
                &base_gen,
                &pedersen,
                &commitments.into_commitments(),
                security_param,
                None
            )
            .is_ok())
    }

    #[test]
    fn exp_proof_valid_with_q() {
        let mut rng = StdRng::from_seed([2; 32]);
        let base_gen = Point::<Secp256k1>::GENERATOR;
        let pedersen = PedersenCycle::<Secp256k1, Tom256k1>::new(&mut rng);

        let q_point = Point::<Secp256k1>::GENERATOR.double();
        let exponent = Scalar::<Secp256k1>::random(&mut rng);
        let result = &Point::<Secp256k1>::GENERATOR.scalar_mul(&exponent) - &q_point;

        let secrets = ExpSecrets::new(exponent, result.into());
        let commitments = secrets.commit(&mut rng, &pedersen);

        let security_param = 10;
        let exp_proof = ExpProof::construct(
            &mut rng,
            &base_gen,
            &pedersen,
            &secrets,
            &commitments,
            security_param,
            Some(q_point.clone()),
        )
        .unwrap();

        assert!(exp_proof
            .verify(
                &mut rng,
                &base_gen,
                &pedersen,
                &commitments.into_commitments(),
                security_param,
                Some(q_point),
            )
            .is_ok())
    }

    #[test]
    fn exp_proof_invalid() {
        let mut rng = StdRng::from_seed([22; 32]);
        let base_gen = Point::<Secp256k1>::GENERATOR;
        let pedersen = PedersenCycle::<Secp256k1, Tom256k1>::new(&mut rng);

        let exponent = Scalar::<Secp256k1>::random(&mut rng);
        let result = Point::<Secp256k1>::GENERATOR.scalar_mul(&(exponent + Scalar::ONE));

        let secrets = ExpSecrets::new(exponent, result.into());
        let commitments = secrets.commit(&mut rng, &pedersen);

        let security_param = 10;
        let exp_proof = ExpProof::construct(
            &mut rng,
            &base_gen,
            &pedersen,
            &secrets,
            &commitments,
            security_param,
            None,
        )
        .unwrap();

        assert!(exp_proof
            .verify(
                &mut rng,
                &base_gen,
                &pedersen,
                &commitments.into_commitments(),
                security_param,
                None
            )
            .is_err());
    }
}
