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
use crate::rng::CryptoCoreRng;

use borsh::{BorshDeserialize, BorshSerialize};

// NOTE 80 is conservative but slow, 40 is faster but quite low security
#[cfg(not(test))]
const SEC_PARAM: usize = 60;
#[cfg(test)]
const SEC_PARAM: usize = 10;

const MSG_PREFIX: &str = "\x19Ethereum Signed Message:\n";
const JOIN_GUILD_MSG: &str = "#zkp/join.guild.xyz/";

/// Zero-knowledge proof consisting of an ECDSA and a Groth-Kohlweiss
/// membership proof.
///
/// Note, that the ring on which the membership proof is generated is not
/// explicitly part of this proof because the backend does additional checks on
/// its integrity before passing it to the veriication function.
#[derive(BorshDeserialize, BorshSerialize)]
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
    pub async fn construct<R: CryptoCoreRng + Send + Sync + Copy>(
        mut rng: R,
        pedersen: PedersenCycle<C, CC>,
        input: ParsedProofInput<C>,
        ring: &ParsedRing<CC>,
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

    pub fn verify<R: CryptoCoreRng + Send + Sync + Copy>(
        &self,
        mut rng: R,
        ring: &ParsedRing<CC>,
    ) -> Result<(), String> {
        let r_point_affine = self.r_point.to_affine();
        if r_point_affine.is_identity() {
            return Err("R is at infinity".to_string());
        }

        let expected_msg = JOIN_GUILD_MSG.to_string() + &self.guild_id;
        let expected_msg_len = expected_msg.as_bytes().len().to_string();
        let preimage = format!("{}{}{}", MSG_PREFIX, expected_msg_len, expected_msg);
        let hasher = PointHasher::new(preimage.as_bytes());
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
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::ZkAttestProof;

    use crate::curve::{Secp256k1, Tom256k1};
    use crate::parse::{parse_ring, ParsedProofInput, ProofInput};
    use crate::pedersen::PedersenCycle;

    #[tokio::test]
    async fn zkp_attest_valid() {
        let mut rng = rand_core::OsRng;
        let pedersen_cycle = PedersenCycle::<Secp256k1, Tom256k1>::new(&mut rng);

        let msg_hash =
            "0x9788117298a1450f6002d25f0c21d83bc6001681a2e5e31c748c0f55504b11e9".to_string();
        let pubkey = "0454e32170dd5a0b7b641aa77daa1f3f31b8df17e51aaba6cfcb310848d26351180b6ac0399d21460443d10072700b64b454d70bfba5e93601536c740bbd099682".to_string();
        let signature = "0xd2943d5fa0ba2733bcbbd58853c6c1be65388d9198dcb5228e117f49409612a46394afb97a7610d16e7bea0062e71afc2a3039324c80df8ef38d3668164fad2c1c".to_string();

        let ring = vec![
            "c2ef144b59081382387f0ebf5d96b3a194f8c28961fa443000ea793ce534dac2".to_string(),
            "54e32170dd5a0b7b641aa77daa1f3f31b8df17e51aaba6cfcb310848d2635118".to_string(), // our pubkey x
            "ddd40afe39c280d2f43f05c070988dae7fbae9cdfd5fb6461acd7657e765e172".to_string(),
            "ccc50afe39c280d2f43f05c070988dae7fbae9cdfd5fb6461acd7657e765e172".to_string(),
            "1296d6ed4e96bc378b8a460de783cdfbf58afbe04b355f1c225fb3e0b92cdc6e".to_string(),
            "aaa70afe39c280d2f43f05c070988dae7fbae9cdfd5fb6461acd7657e765e172".to_string(),
            "bbb80afe39c280d2f43f05c070988dae7fbae9cdfd5fb6461acd7657e765e172".to_string(),
        ];

        let index = 1;

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
        )
        .await
        .unwrap();
        assert!(zkattest_proof.verify(rng, &parsed_ring).is_ok());
    }
}
