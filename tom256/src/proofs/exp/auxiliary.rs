use super::proof::{ExpProofVariant, SingleExpProof};
use super::{ExpCommitments, ExpSecrets};
use crate::arithmetic::AffinePoint;
use crate::arithmetic::{Point, Scalar};
use crate::curve::{Curve, Cycle};
use crate::pedersen::*;
use crate::proofs::point_add::{PointAddProof, PointAddSecrets};

use futures_channel::oneshot::Sender;
use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;

pub struct AuxiliaryCommitments<C: Curve, CC: Cycle<C>> {
    pub alpha: Scalar<C>,
    pub r: Scalar<C>,
    pub a: Point<C>,
    pub t: AffinePoint<C>,
    pub tx: PedersenCommitment<CC>,
    pub ty: PedersenCommitment<CC>,
}

impl<C: Curve, CC: Cycle<C>> AuxiliaryCommitments<C, CC> {
    pub fn generate<R: CryptoRng + RngCore + Send + Sync + Copy>(
        rng: R,
        pedersen: &PedersenCycle<C, CC>,
        base_gen: &Point<C>,
        security_param: usize,
        thread_pool: &rayon::ThreadPool,
        sender: Sender<Vec<AuxiliaryCommitments<C, CC>>>,
    ) {
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
            drop(sender.send(aux_vec))
        });
    }

    pub fn process<R: CryptoRng + RngCore + Send + Sync + Copy>(
        auxiliaries: Vec<Self>,
        rng: R,
        pedersen: &PedersenCycle<C, CC>,
        base_gen: &Point<C>,
        secrets: &ExpSecrets<C>,
        commitments: &ExpCommitments<C, CC>,
        challenge: Vec<bool>,
        q_point: Option<Point<C>>,
        thread_pool: &rayon::ThreadPool,
        sender: Sender<Vec<SingleExpProof<C, CC>>>,
    ) {
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
            drop(sender.send(all_exp_proofs))
        });
    }
}
