use crate::arithmetic::multimult::{MultiMult, Relation};
use crate::arithmetic::AffinePoint;
use crate::arithmetic::{Point, Scalar};
use crate::curve::{Curve, Cycle};
use crate::hasher::PointHasher;
use crate::pedersen::*;
use crate::proofs::point_add::{PointAddCommitmentPoints, PointAddProof, PointAddSecrets};
use crate::rng::CryptoCoreRng;

use bigint::{Encoding, U256};
use borsh::{BorshDeserialize, BorshSerialize};
use futures_channel::oneshot;
use rayon::prelude::*;

use std::ops::Neg;
use std::sync::{Arc, Mutex};

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

struct AuxiliaryCommitments<C: Curve, CC: Cycle<C>> {
    alpha: Scalar<C>,
    r: Scalar<C>,
    a: Point<C>,
    t: AffinePoint<C>,
    tx: PedersenCommitment<CC>,
    ty: PedersenCommitment<CC>,
}

#[derive(BorshDeserialize, BorshSerialize)]
pub struct ExpProof<C: Curve, CC: Cycle<C>> {
    proofs: Vec<SingleExpProof<C, CC>>,
}

impl<CC: Cycle<C>, C: Curve> ExpProof<C, CC> {
    const HASH_ID: &'static [u8] = b"exp-proof";

    pub async fn construct<R: CryptoCoreRng + Send + Sync + Copy>(
        rng: R,
        base_gen: &Point<C>,
        pedersen: &PedersenCycle<C, CC>,
        secrets: &ExpSecrets<C>,
        commitments: &ExpCommitments<C, CC>,
        security_param: usize,
        q_point: Option<Point<C>>,
    ) -> Result<Self, String> {
        let thread_pool = rayon::ThreadPoolBuilder::new()
            .build()
            .map_err(|e| e.to_string())?;

        let (tx, rx) = oneshot::channel();

        thread_pool.install(|| {
            let aux_vec: Vec<AuxiliaryCommitments<C, CC>> = (0..security_param)
                .into_par_iter()
                .map(|_| {
                    let mut rng = rng;
                    // exponent
                    let mut alpha = Scalar::ZERO;
                    while alpha == Scalar::ZERO {
                        // ensure alpha is non-zero
                        alpha = Scalar::random(&mut rng);
                    }
                    // random r scalars
                    let r = Scalar::random(&mut rng);
                    // T = g^alpha
                    let t: AffinePoint<C> = (base_gen * alpha).into();
                    // A = g^alpha + h^r (essentially a commitment in the base curve)
                    let a = &t + &(pedersen.base().generator() * r).to_affine();

                    // commitment to Tx
                    let tx = pedersen.cycle().commit(&mut rng, t.x().to_cycle_scalar());
                    // commitment to Ty
                    let ty = pedersen.cycle().commit(&mut rng, t.y().to_cycle_scalar());

                    AuxiliaryCommitments {
                        alpha,
                        r,
                        a,
                        t,
                        tx,
                        ty,
                    }
                })
                .collect();
            drop(tx.send(aux_vec))
        });

        let auxiliaries = rx.await.map_err(|e| e.to_string())?;
        // NOTE this has to happen here, not in the thread pool because the
        // point hasher can only be passed through an Arc-Mutex pair which
        // inserts points randomly, i.e. the challenge bits will not match
        let mut point_hasher = PointHasher::new(Self::HASH_ID);
        point_hasher.insert_point(commitments.px.commitment());
        point_hasher.insert_point(commitments.py.commitment());
        for aux in &auxiliaries {
            point_hasher.insert_point(&aux.a);
            point_hasher.insert_point(aux.tx.commitment());
            point_hasher.insert_point(aux.ty.commitment());
        }

        let challenge = padded_bits(point_hasher.finalize(), security_param);

        let (tx, rx) = oneshot::channel();

        thread_pool.install(|| {
            let all_exp_proofs = (auxiliaries, challenge)
                .into_par_iter()
                .flat_map(|(aux, c_bit)| {
                    if c_bit {
                        let tx_r = *aux.tx.randomness();
                        let ty_r = *aux.ty.randomness();
                        Ok(SingleExpProof {
                            a: aux.a,
                            tx_p: aux.tx.into_commitment(),
                            ty_p: aux.ty.into_commitment(),
                            variant: ExpProofVariant::Odd {
                                alpha: aux.alpha,
                                r: aux.r,
                                tx_r,
                                ty_r,
                            },
                        })
                    } else {
                        let mut rng = rng;
                        let z = aux.alpha - secrets.exp;
                        let mut t1 = base_gen * z;
                        if let Some(pt) = q_point.as_ref() {
                            t1 += pt;
                        }

                        if t1.is_identity() {
                            return Err("intermediate value is identity".to_owned());
                        }

                        // Generate point add proof
                        let add_secret =
                            PointAddSecrets::new(t1.into(), secrets.point.clone(), aux.t);
                        let add_commitments = add_secret.commit_p_only(
                            &mut rng,
                            pedersen.cycle(),
                            commitments.px.clone(),
                            commitments.py.clone(),
                            aux.tx.clone(),
                            aux.ty.clone(),
                        );
                        let add_proof = PointAddProof::construct(
                            &mut rng,
                            pedersen.cycle(),
                            &add_commitments,
                            &add_secret,
                        );

                        Ok(SingleExpProof {
                            a: aux.a,
                            tx_p: aux.tx.into_commitment(),
                            ty_p: aux.ty.into_commitment(),
                            variant: ExpProofVariant::Even {
                                z,
                                r: aux.r - (*commitments.exp.randomness()),
                                t1_x: *add_commitments.px.randomness(),
                                t1_y: *add_commitments.py.randomness(),
                                add_proof,
                            },
                        })
                    }
                })
                .collect::<Vec<_>>();
            drop(tx.send(all_exp_proofs))
        });

        match rx.await {
            Ok(proofs) => Ok(Self { proofs }),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn verify<R: CryptoCoreRng + Send + Sync + Copy>(
        &self,
        rng: R,
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

        let tom_multimult = Arc::new(Mutex::new(tom_multimult));
        let base_multimult = Arc::new(Mutex::new(base_multimult));

        let mut point_hasher = PointHasher::new(Self::HASH_ID);
        point_hasher.insert_point(&commitments.px);
        point_hasher.insert_point(&commitments.py);

        for i in 0..security_param {
            point_hasher.insert_point(&self.proofs[i].a);
            point_hasher.insert_point(&self.proofs[i].tx_p);
            point_hasher.insert_point(&self.proofs[i].ty_p);
        }

        let challenge = padded_bits(point_hasher.finalize(), self.proofs.len());

        let thread_pool = rayon::ThreadPoolBuilder::new()
            .build()
            .map_err(|e| e.to_string())?;

        thread_pool.install(|| {
            (&self.proofs, challenge)
                .into_par_iter()
                .try_for_each(|(proof, c_bit)| {
                    let mut rng = rng;
                    match &proof.variant {
                        ExpProofVariant::Odd {
                            alpha,
                            r,
                            tx_r,
                            ty_r,
                        } => {
                            if !c_bit {
                                return Err("challenge hash mismatch".to_owned());
                            }

                            let t = base_gen.scalar_mul(alpha);
                            let mut relation_a = Relation::<C>::new();

                            relation_a.insert(t.clone(), Scalar::<C>::ONE);
                            relation_a.insert(pedersen.base().generator().clone(), *r);
                            relation_a.insert((&proof.a).neg(), Scalar::<C>::ONE);

                            relation_a.drain(&mut rng, &mut base_multimult.lock().unwrap());

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
                            relation_tx.insert((&proof.tx_p).neg(), Scalar::<CC>::ONE);

                            relation_ty.insert(Point::<CC>::GENERATOR, sy);
                            relation_ty.insert(pedersen.cycle().generator().clone(), *ty_r);
                            relation_ty.insert((&proof.ty_p).neg(), Scalar::<CC>::ONE);

                            relation_tx.drain(&mut rng, &mut tom_multimult.lock().unwrap());
                            relation_ty.drain(&mut rng, &mut tom_multimult.lock().unwrap());
                            Ok(())
                        }
                        ExpProofVariant::Even {
                            z,
                            r,
                            add_proof,
                            t1_x,
                            t1_y,
                        } => {
                            if c_bit {
                                return Err("challenge hash mismatch".to_owned());
                            }

                            let mut t = base_gen.scalar_mul(z);

                            let mut relation_a = Relation::<C>::new();
                            relation_a.insert(t.clone(), Scalar::<C>::ONE);
                            relation_a.insert(commitments.exp.clone(), Scalar::<C>::ONE);
                            relation_a.insert((&proof.a).neg(), Scalar::<C>::ONE);
                            relation_a.insert(pedersen.base().generator().clone(), *r);

                            relation_a.drain(&mut rng, &mut base_multimult.lock().unwrap());

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
                                proof.tx_p.clone(),
                                proof.ty_p.clone(),
                            );

                            add_proof.aggregate(
                                &mut rng,
                                pedersen.cycle(),
                                &point_add_commitments,
                                &mut tom_multimult.lock().unwrap(),
                            );
                            Ok(())
                        }
                    }
                })
        })?;

        let tom_res = Arc::try_unwrap(tom_multimult)
            .unwrap()
            .into_inner()
            .unwrap()
            .evaluate();
        let base_res = Arc::try_unwrap(base_multimult)
            .unwrap()
            .into_inner()
            .unwrap()
            .evaluate();

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

#[cfg(test)]
mod test {
    use super::*;

    use crate::curve::{Secp256k1, Tom256k1};
    use rand_core::OsRng;

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

    #[tokio::test]
    async fn exp_proof_valid_without_q() {
        let mut rng = OsRng;
        let base_gen = Point::<Secp256k1>::GENERATOR;
        let pedersen = PedersenCycle::<Secp256k1, Tom256k1>::new(&mut rng);

        let exponent = Scalar::<Secp256k1>::random(&mut rng);
        let result = Point::<Secp256k1>::GENERATOR.scalar_mul(&exponent);

        let secrets = ExpSecrets::new(exponent, result.into());
        let commitments = secrets.commit(&mut rng, &pedersen);

        let security_param = 10;
        let exp_proof = ExpProof::construct(
            rng,
            &base_gen,
            &pedersen,
            &secrets,
            &commitments,
            security_param,
            None,
        )
        .await
        .unwrap();

        assert!(exp_proof
            .verify(
                rng,
                &base_gen,
                &pedersen,
                &commitments.into_commitments(),
                security_param,
                None
            )
            .is_ok());
    }

    #[tokio::test]
    async fn exp_proof_valid_with_q() {
        let mut rng = OsRng;
        let base_gen = Point::<Secp256k1>::GENERATOR;
        let pedersen = PedersenCycle::<Secp256k1, Tom256k1>::new(&mut rng);

        let q_point = Point::<Secp256k1>::GENERATOR.double();
        let exponent = Scalar::<Secp256k1>::random(&mut rng);
        let result = &Point::<Secp256k1>::GENERATOR.scalar_mul(&exponent) - &q_point;

        let secrets = ExpSecrets::new(exponent, result.into());
        let commitments = secrets.commit(&mut rng, &pedersen);

        let security_param = 10;
        let exp_proof = ExpProof::construct(
            rng,
            &base_gen,
            &pedersen,
            &secrets,
            &commitments,
            security_param,
            Some(q_point.clone()),
        )
        .await
        .unwrap();

        assert!(exp_proof
            .verify(
                rng,
                &base_gen,
                &pedersen,
                &commitments.into_commitments(),
                security_param,
                Some(q_point),
            )
            .is_ok())
    }

    #[tokio::test]
    async fn exp_proof_invalid() {
        let mut rng = OsRng;
        let base_gen = Point::<Secp256k1>::GENERATOR;
        let pedersen = PedersenCycle::<Secp256k1, Tom256k1>::new(&mut rng);

        let exponent = Scalar::<Secp256k1>::random(&mut rng);
        let result = Point::<Secp256k1>::GENERATOR.scalar_mul(&(exponent + Scalar::ONE));

        let secrets = ExpSecrets::new(exponent, result.into());
        let commitments = secrets.commit(&mut rng, &pedersen);

        let security_param = 10;
        let exp_proof = ExpProof::construct(
            rng,
            &base_gen,
            &pedersen,
            &secrets,
            &commitments,
            security_param,
            None,
        )
        .await
        .unwrap();

        assert!(exp_proof
            .verify(
                rng,
                &base_gen,
                &pedersen,
                &commitments.into_commitments(),
                security_param,
                None
            )
            .is_err());
    }
}
