use crate::arithmetic::multimult::MultiMult;
use crate::arithmetic::AffinePoint;
use crate::arithmetic::{Modular, Point, Scalar};
use crate::curve::{Curve, Cycle};
use crate::pedersen::*;
use crate::rng::CryptoCoreRng;

use super::equality::EqualityProof;
use super::multiplication::MultiplicationProof;

use borsh::{BorshDeserialize, BorshSerialize};
use std::marker::PhantomData;

#[derive(Clone)]
pub struct PointAddSecrets<C: Curve> {
    pub(super) p: AffinePoint<C>,
    pub(super) q: AffinePoint<C>,
    pub(super) r: AffinePoint<C>,
}

impl<C: Curve> PointAddSecrets<C> {
    pub fn new(p: AffinePoint<C>, q: AffinePoint<C>, r: AffinePoint<C>) -> Self {
        // TODO debug_assert!(p + q = r) ?
        Self { p, q, r }
    }

    #[allow(unused)]
    pub fn commit<R, CC>(
        &self,
        rng: &mut R,
        pedersen_generator: &PedersenGenerator<CC>,
    ) -> PointAddCommitments<CC>
    where
        R: CryptoCoreRng,
        CC: Cycle<C>,
    {
        PointAddCommitments {
            px: pedersen_generator.commit(rng, self.p.x().to_cycle_scalar()),
            py: pedersen_generator.commit(rng, self.p.y().to_cycle_scalar()),
            qx: pedersen_generator.commit(rng, self.q.x().to_cycle_scalar()),
            qy: pedersen_generator.commit(rng, self.q.y().to_cycle_scalar()),
            rx: pedersen_generator.commit(rng, self.r.x().to_cycle_scalar()),
            ry: pedersen_generator.commit(rng, self.r.y().to_cycle_scalar()),
        }
    }

    pub fn commit_p_only<R, CC>(
        &self,
        rng: &mut R,
        pedersen_generator: &PedersenGenerator<CC>,
        qx: PedersenCommitment<CC>,
        qy: PedersenCommitment<CC>,
        rx: PedersenCommitment<CC>,
        ry: PedersenCommitment<CC>,
    ) -> PointAddCommitments<CC>
    where
        R: CryptoCoreRng,
        CC: Cycle<C>,
    {
        PointAddCommitments {
            px: pedersen_generator.commit(rng, self.p.x().to_cycle_scalar()),
            py: pedersen_generator.commit(rng, self.p.y().to_cycle_scalar()),
            qx,
            qy,
            rx,
            ry,
        }
    }
}

#[derive(Clone)]
pub struct PointAddCommitments<C: Curve> {
    pub(crate) px: PedersenCommitment<C>,
    pub(crate) py: PedersenCommitment<C>,
    pub(crate) qx: PedersenCommitment<C>,
    pub(crate) qy: PedersenCommitment<C>,
    pub(crate) rx: PedersenCommitment<C>,
    pub(crate) ry: PedersenCommitment<C>,
}

#[cfg(test)]
impl<C: Curve> PointAddCommitments<C> {
    pub fn into_commitments(self) -> PointAddCommitmentPoints<C> {
        PointAddCommitmentPoints {
            px: self.px.into_commitment(),
            py: self.py.into_commitment(),
            qx: self.qx.into_commitment(),
            qy: self.qy.into_commitment(),
            rx: self.rx.into_commitment(),
            ry: self.ry.into_commitment(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PointAddCommitmentPoints<C: Curve> {
    px: Point<C>,
    py: Point<C>,
    qx: Point<C>,
    qy: Point<C>,
    rx: Point<C>,
    ry: Point<C>,
}

impl<C: Curve> PointAddCommitmentPoints<C> {
    pub fn new(
        px: Point<C>,
        py: Point<C>,
        qx: Point<C>,
        qy: Point<C>,
        rx: Point<C>,
        ry: Point<C>,
    ) -> Self {
        Self {
            px,
            py,
            qx,
            qy,
            rx,
            ry,
        }
    }
}

#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct MultCommitProof<C: Curve> {
    commitment: Point<C>,
    proof: MultiplicationProof<C>,
}

impl<C: Curve> MultCommitProof<C> {
    pub fn new(commitment: Point<C>, proof: MultiplicationProof<C>) -> Self {
        Self { commitment, proof }
    }
}

#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct PointAddProof<CC: Cycle<C>, C: Curve> {
    mult_proof_8: MultCommitProof<CC>,
    mult_proof_10: MultCommitProof<CC>,
    mult_proof_11: MultCommitProof<CC>,
    mult_proof_13: MultCommitProof<CC>,
    equality_proof_x: EqualityProof<CC>,
    equality_proof_y: EqualityProof<CC>,
    base_curve: PhantomData<C>,
}

impl<CC: Cycle<C>, C: Curve> PointAddProof<CC, C> {
    pub fn construct<R: CryptoCoreRng>(
        rng: &mut R,
        pedersen_generator: &PedersenGenerator<CC>,
        commitments: &PointAddCommitments<CC>,
        points: &PointAddSecrets<C>,
    ) -> Self {
        // P + Q = R
        // P: (x1, y1)
        // Q: (x2, y2)
        // R: (x3, y3)
        // auxiliary variables (i8 is a type, so use aux8)
        let aux_7 = points.q.x() - points.p.x();
        let aux_8 = aux_7.inverse();
        let aux_9 = points.q.y() - points.p.y();
        let aux_10 = aux_8 * aux_9;
        let aux_11 = aux_10 * aux_10;
        let aux_12 = points.p.x() - points.r.x();
        let aux_13 = aux_10 * aux_12;
        let commitment_7 = &commitments.qx - &commitments.px;
        let commitment_8 = pedersen_generator.commit(rng, aux_8.to_cycle_scalar());
        let commitment_9 = &commitments.qy - &commitments.py;
        let commitment_10 = pedersen_generator.commit(rng, aux_10.to_cycle_scalar());
        let commitment_11 = pedersen_generator.commit(rng, aux_11.to_cycle_scalar());
        let commitment_12 = &commitments.px - &commitments.rx;
        let commitment_13 = pedersen_generator.commit(rng, aux_13.to_cycle_scalar());
        let commitment_14 = PedersenCommitment::new(Point::<CC>::GENERATOR, Scalar::<CC>::ZERO);

        let mult_proof_8 = MultiplicationProof::construct(
            rng,
            pedersen_generator,
            &commitment_7,
            &commitment_8,
            &commitment_14,
            aux_7.to_cycle_scalar(),
            aux_8.to_cycle_scalar(),
            Scalar::<CC>::ONE,
        );
        let mult_proof_10 = MultiplicationProof::construct(
            rng,
            pedersen_generator,
            &commitment_8,
            &commitment_9,
            &commitment_10,
            aux_8.to_cycle_scalar(),
            aux_9.to_cycle_scalar(),
            aux_10.to_cycle_scalar(),
        );
        let mult_proof_11 = MultiplicationProof::construct(
            rng,
            pedersen_generator,
            &commitment_10,
            &commitment_10,
            &commitment_11,
            aux_10.to_cycle_scalar(),
            aux_10.to_cycle_scalar(),
            aux_11.to_cycle_scalar(),
        );

        let aux_commitment = &(&commitments.rx + &commitments.px) + &commitments.qx;
        let equality_proof_x = EqualityProof::construct(
            rng,
            pedersen_generator,
            &commitment_11,
            &aux_commitment,
            aux_11.to_cycle_scalar(),
        );
        let mult_proof_13 = MultiplicationProof::construct(
            rng,
            pedersen_generator,
            &commitment_10,
            &commitment_12,
            &commitment_13,
            aux_10.to_cycle_scalar(),
            aux_12.to_cycle_scalar(),
            aux_13.to_cycle_scalar(),
        );

        let aux_commitment = &commitments.ry + &commitments.py;
        let equality_proof_y = EqualityProof::construct(
            rng,
            pedersen_generator,
            &commitment_13,
            &aux_commitment,
            aux_13.to_cycle_scalar(),
        );

        Self {
            mult_proof_8: MultCommitProof::new(commitment_8.into_commitment(), mult_proof_8),
            mult_proof_10: MultCommitProof::new(commitment_10.into_commitment(), mult_proof_10),
            mult_proof_11: MultCommitProof::new(commitment_11.into_commitment(), mult_proof_11),
            mult_proof_13: MultCommitProof::new(commitment_13.into_commitment(), mult_proof_13),
            equality_proof_x,
            equality_proof_y,
            base_curve: PhantomData,
        }
    }

    pub fn aggregate<R: CryptoCoreRng>(
        &self,
        rng: &mut R,
        pedersen_generator: &PedersenGenerator<CC>,
        commitments: &PointAddCommitmentPoints<CC>,
        multimult: &mut MultiMult<CC>,
    ) {
        let commitment_7 = &commitments.qx - &commitments.px;
        let commitment_9 = &commitments.qy - &commitments.py;
        let commitment_12 = &commitments.px - &commitments.rx;

        // aggregate multiplication proofs
        self.mult_proof_8.proof.aggregate(
            rng,
            pedersen_generator,
            &commitment_7,
            &self.mult_proof_8.commitment,
            &Point::<CC>::GENERATOR,
            multimult,
        );

        self.mult_proof_10.proof.aggregate(
            rng,
            pedersen_generator,
            &self.mult_proof_8.commitment,
            &commitment_9,
            &self.mult_proof_10.commitment,
            multimult,
        );

        self.mult_proof_11.proof.aggregate(
            rng,
            pedersen_generator,
            &self.mult_proof_10.commitment,
            &self.mult_proof_10.commitment,
            &self.mult_proof_11.commitment,
            multimult,
        );

        self.mult_proof_13.proof.aggregate(
            rng,
            pedersen_generator,
            &self.mult_proof_10.commitment,
            &commitment_12,
            &self.mult_proof_13.commitment,
            multimult,
        );
        // aggregate equality proofs
        let aux_commitment = &(&commitments.rx + &commitments.px) + &commitments.qx;
        self.equality_proof_x.aggregate(
            rng,
            pedersen_generator,
            &self.mult_proof_11.commitment,
            &aux_commitment,
            multimult,
        );

        let aux_commitment = &commitments.py + &commitments.ry;
        self.equality_proof_y.aggregate(
            rng,
            pedersen_generator,
            &self.mult_proof_13.commitment,
            &aux_commitment,
            multimult,
        );
    }

    #[cfg(test)]
    pub fn verify<R: CryptoCoreRng>(
        &self,
        rng: &mut R,
        pedersen_generator: &PedersenGenerator<CC>,
        commitments: &PointAddCommitmentPoints<CC>,
    ) -> bool {
        let mut multimult = MultiMult::new();
        self.aggregate(rng, pedersen_generator, commitments, &mut multimult);
        multimult.evaluate().is_identity()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::curve::{Secp256k1, Tom256k1};
    use rand::rngs::StdRng;
    use rand_core::SeedableRng;

    #[test]
    fn valid_point_add_proof() {
        let mut rng = StdRng::from_seed([14; 32]);
        let pedersen_generator = PedersenGenerator::<Tom256k1>::new(&mut rng);

        let p = &Point::<Secp256k1>::GENERATOR * Scalar::<Secp256k1>::random(&mut rng);
        let q = &Point::<Secp256k1>::GENERATOR * Scalar::<Secp256k1>::random(&mut rng);
        let r = &p + &q;
        let secret = PointAddSecrets::new(p.into(), q.into(), r.into());
        let commitments = secret.commit(&mut rng, &pedersen_generator);

        let proof = PointAddProof::construct(&mut rng, &pedersen_generator, &commitments, &secret);

        assert!(proof.verify(
            &mut rng,
            &pedersen_generator,
            &commitments.into_commitments()
        ));
    }

    #[test]
    fn invalid_point_add_proof() {
        let mut rng = StdRng::from_seed([14; 32]);
        let pedersen_generator = PedersenGenerator::<Tom256k1>::new(&mut rng);

        let p = &Point::<Secp256k1>::GENERATOR * Scalar::<Secp256k1>::random(&mut rng);
        let q = &Point::<Secp256k1>::GENERATOR * Scalar::<Secp256k1>::random(&mut rng);
        let r = (&p + &q) + Point::<Secp256k1>::GENERATOR; // invalid sum
        let secret = PointAddSecrets::new(p.into(), q.into(), r.into());
        let commitments = secret.commit(&mut rng, &pedersen_generator);

        let proof = PointAddProof::construct(&mut rng, &pedersen_generator, &commitments, &secret);

        assert!(!proof.verify(
            &mut rng,
            &pedersen_generator,
            &commitments.into_commitments()
        ));
    }

    #[ignore]
    #[test]
    fn aggregate_valid_proofs() {
        let mut rng = StdRng::from_seed([119; 32]);
        let pedersen_generator = PedersenGenerator::<Tom256k1>::new(&mut rng);

        let mut multimult = MultiMult::new();
        for _ in 0..50 {
            let p = &Point::<Secp256k1>::GENERATOR * Scalar::<Secp256k1>::random(&mut rng);
            let q = &Point::<Secp256k1>::GENERATOR * Scalar::<Secp256k1>::random(&mut rng);
            let r = &p + &q;
            let secret = PointAddSecrets::new(p.into(), q.into(), r.into());
            let commitments = secret.commit(&mut rng, &pedersen_generator);

            let proof =
                PointAddProof::construct(&mut rng, &pedersen_generator, &commitments, &secret);
            proof.aggregate(
                &mut rng,
                &pedersen_generator,
                &commitments.into_commitments(),
                &mut multimult,
            );
        }
        assert!(multimult.evaluate().is_identity());
    }
}
