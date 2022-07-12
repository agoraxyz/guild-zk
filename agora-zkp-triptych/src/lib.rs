#![feature(int_log)]

#[cfg(test)]
mod keypair;
pub mod ring;
pub mod signature;
mod utils;

use generic_array::GenericArray;
use k256::elliptic_curve::PrimeField;
use k256::Scalar;
use ring::*;
use signature::{Parameters, Signature};

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

const MAX_2_EXPONENT: usize = 20;

#[derive(Clone, Serialize, Deserialize)]
pub struct Proof {
    pub parameters: Parameters,
    pub signature: Signature,
}

// XXX use serde_json initially for serialization
// then switch to borsh

#[wasm_bindgen]
pub fn sign(
    msg_hash: String,
    privkey: String,
    index: u32,
    ring: JsValue,
) -> Result<JsValue, JsValue> {
    let parameters = Parameters::new(MAX_2_EXPONENT);

    let frontend_ring: FrontendRing = ring.into_serde().map_err(|e| e.to_string())?;
    let ring = parse_ring(frontend_ring)?;
    let parsed_msg_hash = parse_msg_hash(&msg_hash)?;
    let parsed_privkey = parse_privkey(&privkey)?;

    let signature = Signature::new(
        index as usize,
        &ring,
        &parsed_msg_hash,
        parsed_privkey,
        &parameters,
    )?;

    let proof = Proof {
        parameters,
        signature,
    };
    JsValue::from_serde(&proof).map_err(|e| e.to_string().into())
}

#[wasm_bindgen]
pub fn verify(msg_hash: String, proof: JsValue, ring: JsValue) -> Result<JsValue, JsValue> {
    let proof: Proof = proof.into_serde().map_err(|e| e.to_string())?;
    let frontend_ring: FrontendRing = ring.into_serde().map_err(|e| e.to_string())?;
    let ring = parse_ring(frontend_ring)?;
    let parsed_msg_hash = parse_msg_hash(&msg_hash)?;

    proof
        .signature
        .verify(&ring, &parsed_msg_hash, &proof.parameters)?;
    Ok(JsValue::from("Proof OK"))
}

fn parse_hex_str_to_array(input: &str) -> Result<[u8; 32], String> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(input.trim_start_matches("0x"), &mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}

fn parse_privkey(privkey: &str) -> Result<Scalar, String> {
    let privkey_bytes = parse_hex_str_to_array(privkey)?;
    let opt = Scalar::from_repr(*GenericArray::from_slice(&privkey_bytes));
    if opt.is_some().unwrap_u8() == 0 {
        Err("failed to parse privkey".to_owned())
    } else {
        Ok(opt.unwrap())
    }
}

fn parse_msg_hash(msg_hash: &str) -> Result<[u8; 32], String> {
    parse_hex_str_to_array(msg_hash)
}

#[cfg(test)]
mod test {
    use super::*;
    use k256::elliptic_curve::Field;
    use rand_core::OsRng;

    #[test]
    fn parse_privkey_from_str() {
        for _ in 0..10 {
            let privkey = Scalar::random(OsRng);
            let privkey_hex_string = hex::encode(privkey.to_bytes());
            let parsed = parse_privkey(&privkey_hex_string).unwrap();
            assert_eq!(privkey, parsed);
        }
    }
}
