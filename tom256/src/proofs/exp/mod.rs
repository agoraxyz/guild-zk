mod auxiliary;
mod proof;

pub use auxiliary::*;
pub use proof::ExpProof;

use crate::arithmetic::AffinePoint;
use crate::arithmetic::{Point, Scalar};
use crate::curve::{Curve, Cycle};
use crate::pedersen::*;

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct ExpSecrets<C: Curve> {
    point: AffinePoint<C>,
    exp: Scalar<C>,
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
        R: CryptoRng + RngCore,
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

#[derive(Clone, Serialize, Deserialize)]
pub struct ExpCommitments<C: Curve, CC: Cycle<C>> {
    pub px: PedersenCommitment<CC>,
    pub py: PedersenCommitment<CC>,
    pub exp: PedersenCommitment<C>,
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

#[derive(Clone, Serialize, Deserialize)]
pub struct ExpCommitmentPoints<C: Curve, CC: Cycle<C>> {
    pub(super) px: Point<CC>,
    pub(super) py: Point<CC>,
    pub(super) exp: Point<C>,
}

impl<C: Curve, CC: Cycle<C>> ExpCommitmentPoints<C, CC> {
    pub fn new(exp: Point<C>, px: Point<CC>, py: Point<CC>) -> Self {
        Self { exp, px, py }
    }
}
