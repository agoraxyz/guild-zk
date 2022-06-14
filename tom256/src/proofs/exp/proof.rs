use super::auxiliary::AuxiliaryCommitments;
use super::{ExpCommitmentPoints, ExpCommitments, ExpSecrets};
use crate::arithmetic::multimult::{MultiMult, Relation};
use crate::arithmetic::AffinePoint;
use crate::arithmetic::{Point, Scalar};
use crate::curve::{Curve, Cycle};
use crate::hasher::PointHasher;
use crate::pedersen::PedersenCycle;
use crate::proofs::point_add::{PointAddCommitmentPoints, PointAddProof};
#[cfg(target_arch = "wasm32")]
use crate::worker_pool::WorkerPool;

use bigint::{Encoding, U256};
use futures_channel::oneshot;
use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use std::ops::Neg;
use std::sync::{Arc, Mutex};

#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
pub struct SingleExpProof<C: Curve, CC: Cycle<C>> {
    pub a: Point<C>,
    pub tx_p: Point<CC>,
    pub ty_p: Point<CC>,
    pub variant: ExpProofVariant<C, CC>,
}

#[derive(Serialize, Deserialize)]
pub struct ExpProof<C: Curve, CC: Cycle<C>> {
    proofs: Vec<SingleExpProof<C, CC>>,
}

impl<CC: Cycle<C>, C: Curve> ExpProof<C, CC> {
    const HASH_ID: &'static [u8] = b"exp-proof";

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn construct<R: CryptoRng + RngCore + Send + Sync + Copy>(
        rng: R,
        base_gen: &Point<C>,
        pedersen: &PedersenCycle<C, CC>,
        secrets: &ExpSecrets<C>,
        commitments: &ExpCommitments<C, CC>,
        security_param: usize,
        q_point: Option<Point<C>>,
        thread_pool: &rayon::ThreadPool,
    ) -> Result<Self, String> {
        let (tx, rx) = oneshot::channel();
        AuxiliaryCommitments::generate(rng, pedersen, base_gen, security_param, thread_pool, tx);
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

        AuxiliaryCommitments::process(
            auxiliaries,
            rng,
            pedersen,
            base_gen,
            secrets,
            commitments,
            challenge,
            q_point,
            thread_pool,
            tx,
        );

        let proofs = rx.await.map_err(|e| e.to_string())?;
        Ok(Self { proofs })
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn construct<R: CryptoRng + RngCore + Send + Sync + Copy>(
        rng: R,
        base_gen: &Point<C>,
        pedersen: &PedersenCycle<C, CC>,
        secrets: &ExpSecrets<C>,
        commitments: &ExpCommitments<C, CC>,
        security_param: usize,
        q_point: Option<Point<C>>,
        thread_pool: &rayon::ThreadPool,
        worker_pool: &WorkerPool,
    ) -> Result<Self, String> {
        let (tx, rx) = oneshot::channel();
        worker_pool.run(move || {
            AuxiliaryCommitments::generate(rng, pedersen, base_gen, security_param, thread_pool, tx)
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

        worker_pool.run(move || {
            AuxiliaryCommitments::process(
                auxiliaries,
                rng,
                pedersen,
                base_gen,
                secrets,
                commitments,
                challenge,
                q_point,
                thread_pool,
                tx,
            )
        });

        let proofs = rx.await.map_err(|e| e.to_string())?;
        Ok(Self { proofs })
    }

    pub fn verify<R: CryptoRng + RngCore + Send + Sync + Copy>(
        &self,
        rng: R,
        base_gen: &Point<C>,
        pedersen: &PedersenCycle<C, CC>,
        commitments: &ExpCommitmentPoints<C, CC>,
        security_param: usize,
        q_point: Option<Point<C>>,
        thread_pool: &rayon::ThreadPool,
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

        // TODO do we need indices (sec param == proof.len())
        //let indices = generate_indices(security_param, self.proofs.len(), &mut rng);
        let challenge = padded_bits(point_hasher.finalize(), self.proofs.len());

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

    use crate::build_thread_pool;
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
        let thread_pool = build_thread_pool().unwrap();

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
            &thread_pool,
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
                None,
                &thread_pool,
            )
            .is_ok());
    }

    #[tokio::test]
    async fn exp_proof_valid_with_q() {
        let mut rng = OsRng;
        let base_gen = Point::<Secp256k1>::GENERATOR;
        let pedersen = PedersenCycle::<Secp256k1, Tom256k1>::new(&mut rng);
        let thread_pool = build_thread_pool().unwrap();

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
            &thread_pool,
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
                &thread_pool,
            )
            .is_ok())
    }

    #[tokio::test]
    async fn exp_proof_invalid() {
        let mut rng = OsRng;
        let base_gen = Point::<Secp256k1>::GENERATOR;
        let pedersen = PedersenCycle::<Secp256k1, Tom256k1>::new(&mut rng);
        let thread_pool = build_thread_pool().unwrap();

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
            &thread_pool,
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
                None,
                &thread_pool
            )
            .is_err());
    }
}
