#![feature(int_log)]
pub mod arithmetic;
pub mod curve;
mod hasher;
pub mod parse;
pub mod pedersen;
pub mod proofs;
mod rng;

use arithmetic::Point;
pub use bigint::U256;
use borsh::BorshSerialize;
use curve::{Secp256k1, Tom256k1};
use parse::*;
use pedersen::PedersenCycle;
use proofs::ZkAttestProof;
use wasm_bindgen::prelude::*;

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofOutput {
    guild_id: String,
    r_point: Point<Secp256k1>,
    proof_binary: Vec<u8>,
}

#[wasm_bindgen(js_name = "generateProof")]
pub fn generate_proof(input: JsValue, ring: JsValue) -> Result<JsValue, JsValue> {
    let mut rng = rand_core::OsRng;
    let pedersen = PedersenCycle::<Secp256k1, Tom256k1>::new(&mut rng);

    let input: ParsedProofInput<Secp256k1> = input
        .into_serde::<ProofInput>()
        .map_err(|e| e.to_string())?
        .try_into()?;

    let ring: ParsedRing<Tom256k1> =
        parse_ring(ring.into_serde::<Ring>().map_err(|e| e.to_string())?)?;

    let zk_attest_proof = ZkAttestProof::construct(&mut rng, pedersen, input, &ring)?;

    let proof_binary = zk_attest_proof
        .try_to_vec()
        .map_err(|e| JsValue::from(e.to_string()))?;

    let proof_output = ProofOutput {
        guild_id: zk_attest_proof.guild_id,
        r_point: zk_attest_proof.r_point,
        proof_binary,
    };

    JsValue::from_serde(&proof_output).map_err(|e| JsValue::from(e.to_string()))
}

// This function is only for wasm test purposes as the
// verification is done on the backend in pure rust.
// TODO: put this behind a wasm-test feature flag?
#[wasm_bindgen(js_name = "verifyProof")]
pub fn verify_proof(proof: Vec<u8>, ring: JsValue) -> Result<JsValue, JsValue> {
    let mut rng = rand_core::OsRng;

    let proof: ZkAttestProof<Secp256k1, Tom256k1> =
        borsh::BorshDeserialize::try_from_slice(proof.as_slice()).map_err(|e| e.to_string())?;

    let ring: ParsedRing<Tom256k1> =
        parse_ring(ring.into_serde::<Ring>().map_err(|e| e.to_string())?)?;

    proof.verify(&mut rng, &ring)?;
    Ok(JsValue::from(true))
}
