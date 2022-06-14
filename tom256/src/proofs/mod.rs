mod equality;
mod exp;
mod membership;
mod multiplication;
mod point_add;
mod utils;

// TODO these does not need to be public
pub use exp::{ExpCommitmentPoints, ExpCommitments, ExpProof, ExpSecrets};
pub use membership::MembershipProof;

use crate::arithmetic::{Modular, Point, Scalar};
use crate::curve::{Curve, Cycle};
use crate::hasher::PointHasher;
use crate::parse::{ParsedProofInput, ParsedRing};
use crate::pedersen::PedersenCycle;

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

// NOTE 80 is conservative but slow, 40 is faster but quite low security
#[cfg(not(test))]
const SEC_PARAM: usize = 60;
#[cfg(test)]
const SEC_PARAM: usize = 10;

const JOIN_GUILD_MSG: &str = "#zkp/join.guild.xyz/";

/// Zero-knowledge proof consisting of an ECDSA and a Groth-Kohlweiss
/// membership proof.
///
/// Note, that the ring on which the membership proof is generated is not
/// explicitly part of this proof because the backend does additional checks on
/// its integrity before passing it to the veriication function.
#[derive(Deserialize, Serialize)]
pub struct ZkAttestProof<C: Curve, CC: Cycle<C>> {
    pub pedersen: PedersenCycle<C, CC>,
    pub msg_hash: Scalar<C>,
    pub r_point: Point<C>,
    pub exp_commitments: ExpCommitmentPoints<C, CC>, // s1, pkx, pxy
    pub signature_proof: ExpProof<C, CC>,
    pub membership_proof: MembershipProof<CC>,
    pub guild_id: String,
}

impl<C: Curve, CC: Cycle<C>> ZkAttestProof<C, CC> {
    pub async fn construct<R: CryptoRng + RngCore + Send + Sync + Copy>(
        mut rng: R,
        pedersen: PedersenCycle<C, CC>,
        input: ParsedProofInput<C>,
        ring: &ParsedRing<CC>,
        thread_pool: &rayon::ThreadPool,
    ) -> Result<Self, String> {
        let s_inv = input.signature.s.inverse();
        let r_inv = input.signature.r.inverse();
        let u1 = s_inv * input.msg_hash;
        let u2 = s_inv * input.signature.r;
        let r_point = Point::<C>::GENERATOR.double_mul(&u1, &Point::from(&input.pubkey), &u2);
        let s1 = r_inv * input.signature.s;
        let z1 = r_inv * input.msg_hash;
        let q_point = &Point::<C>::GENERATOR * z1;

        let commitment_to_s1 = pedersen
            .base()
            .commit_with_generator(&mut rng, s1, &r_point);
        let commitment_to_pk_x = pedersen
            .cycle()
            .commit(&mut rng, input.pubkey.x().to_cycle_scalar());
        let commitment_to_pk_y = pedersen
            .cycle()
            .commit(&mut rng, input.pubkey.y().to_cycle_scalar());

        // generate membership proof on pubkey x coordinate
        let membership_proof = MembershipProof::construct(
            &mut rng,
            pedersen.cycle(),
            &commitment_to_pk_x,
            input.index,
            ring,
        )?;

        // generate ECDSA proof on signature
        let exp_secrets = ExpSecrets::new(s1, input.pubkey);
        let exp_commitments = ExpCommitments {
            px: commitment_to_pk_x,
            py: commitment_to_pk_y,
            exp: commitment_to_s1,
        };

        let signature_proof = ExpProof::construct(
            rng,
            &r_point,
            &pedersen,
            &exp_secrets,
            &exp_commitments,
            SEC_PARAM,
            Some(q_point),
            thread_pool,
        )
        .await?;

        Ok(Self {
            pedersen,
            msg_hash: input.msg_hash,
            r_point,
            exp_commitments: exp_commitments.into_commitments(),
            signature_proof,
            membership_proof,
            guild_id: input.guild_id,
        })
    }

    pub fn verify<R: CryptoRng + RngCore + Send + Sync + Copy>(
        &self,
        mut rng: R,
        ring: &ParsedRing<CC>,
        thread_pool: &rayon::ThreadPool,
    ) -> Result<(), String> {
        let r_point_affine = self.r_point.to_affine();
        if r_point_affine.is_identity() {
            return Err("R is at infinity".to_string());
        }

        let expected_msg = JOIN_GUILD_MSG.to_string() + &self.guild_id;
        let hasher = PointHasher::new(expected_msg.as_bytes());
        let expected_hash = Scalar::<C>::new(hasher.finalize());
        if expected_hash != self.msg_hash {
            return Err("Signed message hash mismatch".to_string());
        }

        // NOTE weird: a field element Rx is converted
        // directly into a scalar
        let r_inv = Scalar::<C>::new(*r_point_affine.x().inner()).inverse();
        let z1 = r_inv * self.msg_hash;
        let q_point = &Point::<C>::GENERATOR * z1;

        self.membership_proof.verify(
            &mut rng,
            self.pedersen.cycle(),
            &self.exp_commitments.px,
            ring,
        )?;

        self.signature_proof.verify(
            rng,
            &self.r_point,
            &self.pedersen,
            &self.exp_commitments,
            SEC_PARAM,
            Some(q_point),
            thread_pool,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::ZkAttestProof;

    use crate::build_thread_pool;
    use crate::curve::{Secp256k1, Tom256k1};
    use crate::parse::{parse_ring, ParsedProofInput, ProofInput};
    use crate::pedersen::PedersenCycle;

    #[tokio::test]
    async fn zkp_attest_valid() {
        let mut rng = rand_core::OsRng;
        let pedersen_cycle = PedersenCycle::<Secp256k1, Tom256k1>::new(&mut rng);
        let thread_pool = build_thread_pool().unwrap();

        let msg_hash =
            "0x2c31a901b06d2727f458c7eb5c15eb7a794d69f841970f95c39ac092274c2a5a".to_string();
        let pubkey =
            "0x041296d6ed4e96bc378b8a460de783cdfbf58afbe04b355f1c225fb3e0b92cdc6e349d7005833c933898e2b88eae1cf40250c16352ace3915de65ec86f5bb9b349".to_string();
        let signature =
            "0xc945f22f92bc9afa7c8929637d3f8694b95a6ae9e276103b2061a0f88d61d8e92aaa9b9eec482d8befd1e1d2a9e2e219f21bd660278aefa9b0641184280cc2d91b".to_string();

        let ring = vec![
            "ddd40afe39c280d2f43f05c070988dae7fbae9cdfd5fb6461acd7657e765e172".to_string(),
            "ccc50afe39c280d2f43f05c070988dae7fbae9cdfd5fb6461acd7657e765e172".to_string(),
            "1296d6ed4e96bc378b8a460de783cdfbf58afbe04b355f1c225fb3e0b92cdc6e".to_string(), // our pubkey x
            "aaa70afe39c280d2f43f05c070988dae7fbae9cdfd5fb6461acd7657e765e172".to_string(),
            "bbb80afe39c280d2f43f05c070988dae7fbae9cdfd5fb6461acd7657e765e172".to_string(),
        ];

        let index = 2;

        let proof_input = ProofInput {
            msg_hash,
            pubkey,
            signature,
            index,
            guild_id: "almafa".to_string(),
        };

        let parsed_input: ParsedProofInput<Secp256k1> = proof_input.try_into().unwrap();
        let parsed_ring = parse_ring(ring).unwrap();

        let zkattest_proof = ZkAttestProof::<Secp256k1, Tom256k1>::construct(
            rng,
            pedersen_cycle,
            parsed_input,
            &parsed_ring,
            &thread_pool,
        )
        .await
        .unwrap();
        assert!(zkattest_proof
            .verify(rng, &parsed_ring, &thread_pool)
            .is_ok());
    }
}
