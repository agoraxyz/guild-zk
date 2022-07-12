use super::utils::*;
use crate::arithmetic::multimult::*;
use crate::arithmetic::{Modular, Point, Scalar};
use crate::curve::Curve;
use crate::hasher::PointHasher;
use crate::pedersen::*;
use crate::rng::CryptoCoreRng;
use crate::U256;

use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct MembershipProof<C: Curve> {
    cl: Vec<Point<C>>,
    ca: Vec<Point<C>>,
    cb: Vec<Point<C>>,
    cd: Vec<Point<C>>,
    fi: Vec<Scalar<C>>,
    za: Vec<Scalar<C>>,
    zb: Vec<Scalar<C>>,
    zd: Scalar<C>,
}

impl<C: Curve> MembershipProof<C> {
    const HASH_ID: &'static [u8] = b"membership-proof";

    pub fn construct<R: CryptoCoreRng>(
        rng: &mut R,
        pedersen_generator: &PedersenGenerator<C>,
        commitment_to_key: &PedersenCommitment<C>,
        index: usize,
        // NOTE this is just the public address represented as a scalar (only
        // 160 bit, so it should fit unless C::PRIME_MODULUS is less than
        // 2^160)
        ring: &[Scalar<C>],
    ) -> Result<Self, String> {
        if index >= ring.len() {
            return Err("invalid index".to_string());
        }

        let mut ring = ring.to_vec();
        let n = pad_ring_to_2n(&mut ring)?; // log2(ring.len())

        // random scalar storages
        let mut a_vec = Vec::<Scalar<C>>::with_capacity(n);
        let mut l_vec = Vec::<Scalar<C>>::with_capacity(n);
        let mut r_vec = Vec::<Scalar<C>>::with_capacity(n);
        let mut s_vec = Vec::<Scalar<C>>::with_capacity(n);
        let mut t_vec = Vec::<Scalar<C>>::with_capacity(n);
        let mut rho_vec = Vec::<Scalar<C>>::with_capacity(n);

        // commitment storages
        let mut ca = Vec::<Point<C>>::with_capacity(n);
        let mut cb = Vec::<Point<C>>::with_capacity(n);
        let mut cd = Vec::<Point<C>>::with_capacity(n);
        let mut cl = Vec::<Point<C>>::with_capacity(n);

        let mut omegas = Vec::<Scalar<C>>::with_capacity(n);

        let mut tmp_index = index;
        for i in 0..n {
            l_vec.push(Scalar::new(U256::from_u64((tmp_index % 2) as u64)));
            tmp_index /= 2;
            a_vec.push(Scalar::random(rng));
            r_vec.push(Scalar::random(rng));
            s_vec.push(Scalar::random(rng));
            t_vec.push(Scalar::random(rng));
            rho_vec.push(Scalar::random(rng));

            cl.push(
                pedersen_generator
                    .commit_with_randomness(l_vec[i], r_vec[i])
                    .into_commitment(),
            );
            ca.push(
                pedersen_generator
                    .commit_with_randomness(a_vec[i], s_vec[i])
                    .into_commitment(),
            );
            cb.push(
                pedersen_generator
                    .commit_with_randomness(l_vec[i] * a_vec[i], t_vec[i])
                    .into_commitment(),
            );

            omegas.push(Scalar::new(U256::from_u64(i as u64)));
        }

        let mut poly_vals = Vec::<Scalar<C>>::new();
        for omega in omegas.iter() {
            let mut f0j = Vec::<Scalar<C>>::with_capacity(n);
            let mut f1j = Vec::<Scalar<C>>::with_capacity(n);
            let mut ratio = Vec::<Scalar<C>>::with_capacity(n);

            let mut product = Scalar::ONE;
            for j in 0..n {
                f0j.push(&(Scalar::ONE - l_vec[j]) * omega - a_vec[j]);
                f1j.push(&l_vec[j] * omega + a_vec[j]);
                ratio.push(f1j[j] * f0j[j].inverse());
                product *= f0j[j];
            }

            let mut prod_vec = vec![product];

            for r in ratio.iter().take(n) {
                let old_p_len = prod_vec.len();
                for j in 0..old_p_len {
                    prod_vec.push(r * &prod_vec[j]);
                }
            }

            let mut poly_val = Scalar::ZERO;
            for i in 0..ring.len() {
                poly_val += (ring[index] - ring[i]) * prod_vec[i];
            }
            poly_vals.push(poly_val);
        }

        let coeffs = interpolate(&omegas, &poly_vals)?;
        for i in 0..n {
            cd.push(
                pedersen_generator
                    .commit_with_randomness(coeffs[i], rho_vec[i])
                    .into_commitment(),
            );
        }

        if cl.len() != n || ca.len() != n || cb.len() != n || cd.len() != n {
            return Err("invalid commitment lengths".to_owned());
        }

        let challenge = Self::hash_commitments(&ca, &cb, &cd, &cl);
        let mut fi = Vec::<Scalar<C>>::with_capacity(n);
        let mut za = Vec::<Scalar<C>>::with_capacity(n);
        let mut zb = Vec::<Scalar<C>>::with_capacity(n);
        let mut zd =
            commitment_to_key.randomness() * &challenge.pow(&Scalar::new(U256::from_u64(n as u64)));

        for i in 0..n {
            fi.push(l_vec[i] * challenge + a_vec[i]);
            za.push(r_vec[i] * challenge + s_vec[i]);
            zb.push(r_vec[i] * (challenge - fi[i]) + t_vec[i]);
            zd -= rho_vec[i] * challenge.pow(&Scalar::new(U256::from_u64(i as u64)));
        }

        if fi.len() != n || za.len() != n || zb.len() != n {
            return Err("invalid proof lengths".to_owned());
        }

        Ok(Self {
            cl,
            ca,
            cb,
            cd,
            fi,
            za,
            zb,
            zd,
        })
    }

    pub fn verify<R: CryptoCoreRng>(
        &self,
        rng: &mut R,
        pedersen_generator: &PedersenGenerator<C>,
        commitment_to_key: &Point<C>,
        ring: &[Scalar<C>],
    ) -> Result<(), String> {
        let mut ring = ring.to_vec();
        let n = pad_ring_to_2n(&mut ring)?; // log2(ring.len())

        let challenge = Self::hash_commitments(&self.ca, &self.cb, &self.cd, &self.cl);

        let mut multimult = MultiMult::new();
        multimult.add_known(Point::<C>::GENERATOR);
        multimult.add_known(pedersen_generator.generator().clone());

        // NOTE unwraps here are fine because of length checks
        // at proof construction
        for i in 0..n {
            let mut rel_0 = Relation::new();
            let mut rel_1 = Relation::new();

            rel_0.insert(self.cl.get(i).unwrap().clone(), challenge);
            rel_0.insert(self.ca.get(i).unwrap().clone(), Scalar::ONE);
            rel_0.insert(Point::<C>::GENERATOR, -self.fi[i]);
            rel_0.insert(pedersen_generator.generator().clone(), -self.za[i]);

            rel_1.insert(self.cl.get(i).unwrap().clone(), challenge - self.fi[i]);
            rel_1.insert(self.cb.get(i).unwrap().clone(), Scalar::ONE);
            rel_1.insert(pedersen_generator.generator().clone(), -self.zb[i]);

            rel_0.drain(rng, &mut multimult);
            rel_1.drain(rng, &mut multimult);
        }

        let mut total = Scalar::ZERO;
        for (i, key) in ring.iter().enumerate() {
            let mut pix = Scalar::ONE;
            for j in 0..n {
                if i & (1 << j) == 0 {
                    pix *= challenge - self.fi[j];
                } else {
                    pix *= self.fi[j];
                }
            }
            total += key * &pix;
        }

        let mut rel_final = Relation::new();
        for (i, cd_elem) in self.cd.iter().enumerate() {
            rel_final.insert(
                cd_elem.clone(),
                -challenge.pow(&Scalar::new(U256::from_u64(i as u64))),
            );
        }

        rel_final.insert(
            commitment_to_key.clone(),
            challenge.pow(&Scalar::new(U256::from_u64(n as u64))),
        );
        rel_final.insert(Point::<C>::GENERATOR, -total);
        rel_final.insert(pedersen_generator.generator().clone(), -self.zd);
        rel_final.drain(rng, &mut multimult);

        if multimult.evaluate().is_identity() {
            Ok(())
        } else {
            Err("failed to verify membership".to_owned())
        }
    }

    fn hash_commitments(
        ca: &[Point<C>],
        cb: &[Point<C>],
        cd: &[Point<C>],
        cl: &[Point<C>],
    ) -> Scalar<C> {
        let mut hasher = PointHasher::new(Self::HASH_ID);
        // NOTE we are assuming that all input slices have the same length
        // it is important to use this function in both `contruct` and `verify`
        for i in 0..ca.len() {
            hasher.insert_point(ca.get(i).unwrap());
            hasher.insert_point(cb.get(i).unwrap());
            hasher.insert_point(cd.get(i).unwrap());
            hasher.insert_point(cl.get(i).unwrap());
        }

        Scalar::<C>::new(hasher.finalize())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::curve::Tom256k1;
    use rand::rngs::StdRng;
    use rand_core::SeedableRng;

    #[test]
    fn valid_membership_proof() {
        let mut rng = StdRng::from_seed([117; 32]);
        let pedersen_generator = PedersenGenerator::<Tom256k1>::new(&mut rng);
        let ring = vec![
            Scalar::<Tom256k1>::new(U256::from_u8(0)),
            Scalar::<Tom256k1>::new(U256::from_u8(1)),
            Scalar::<Tom256k1>::new(U256::from_u8(2)),
            Scalar::<Tom256k1>::new(U256::from_u8(3)),
            Scalar::<Tom256k1>::new(U256::from_u8(4)),
            Scalar::<Tom256k1>::new(U256::from_u8(5)),
            Scalar::<Tom256k1>::new(U256::from_u8(6)),
            Scalar::<Tom256k1>::new(U256::from_u8(7)),
        ];

        let index = 1_usize;
        let commitment_to_key = pedersen_generator.commit(&mut rng, ring[index]);

        let proof = MembershipProof::construct(
            &mut rng,
            &pedersen_generator,
            &commitment_to_key,
            index,
            &ring,
        )
        .unwrap();

        assert!(proof
            .verify(
                &mut rng,
                &pedersen_generator,
                commitment_to_key.commitment(),
                &ring,
            )
            .is_ok());
    }

    #[test]
    fn valid_membership_proof_long() {
        let mut rng = StdRng::from_seed([117; 32]);
        let pedersen_generator = PedersenGenerator::<Tom256k1>::new(&mut rng);
        let n = 1024_u32;
        let mut ring = Vec::<Scalar<Tom256k1>>::with_capacity(n as usize);
        for i in 0..n {
            ring.push(Scalar::new(U256::from_u32(i)));
        }
        let index = 452_usize;
        let commitment_to_key = pedersen_generator.commit(&mut rng, ring[index]);
        let proof = MembershipProof::construct(
            &mut rng,
            &pedersen_generator,
            &commitment_to_key,
            index,
            &ring,
        )
        .unwrap();

        assert!(proof
            .verify(
                &mut rng,
                &pedersen_generator,
                commitment_to_key.commitment(),
                &ring,
            )
            .is_ok());
    }

    #[test]
    fn invalid_membership_proof() {
        let mut rng = StdRng::from_seed([117; 32]);
        let pedersen_generator = PedersenGenerator::<Tom256k1>::new(&mut rng);
        let ring = vec![
            Scalar::<Tom256k1>::new(U256::from_u8(0)),
            Scalar::<Tom256k1>::new(U256::from_u8(1)),
            Scalar::<Tom256k1>::new(U256::from_u8(2)),
            Scalar::<Tom256k1>::new(U256::from_u8(3)),
            Scalar::<Tom256k1>::new(U256::from_u8(4)),
            Scalar::<Tom256k1>::new(U256::from_u8(5)),
            Scalar::<Tom256k1>::new(U256::from_u8(6)),
            Scalar::<Tom256k1>::new(U256::from_u8(7)),
        ];

        let index = 1_usize;
        let commitment_to_key = pedersen_generator.commit(&mut rng, ring[index + 1]);
        let proof = MembershipProof::construct(
            &mut rng,
            &pedersen_generator,
            &commitment_to_key,
            index,
            &ring,
        )
        .unwrap();

        assert_eq!(
            proof.verify(
                &mut rng,
                &pedersen_generator,
                commitment_to_key.commitment(),
                &ring,
            ),
            Err("failed to verify membership".to_string())
        );
    }
}
