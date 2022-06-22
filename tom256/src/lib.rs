#![feature(int_log)]

// this macro needs to come before 'mod worker_pool'
#[cfg(target_arch = "wasm32")]
macro_rules! console_log {
    ($($t:tt)*) => (crate::log(&format_args!($($t)*).to_string()))
}

pub mod arithmetic;
pub mod curve;
mod hasher;
pub mod parse;
pub mod pedersen;
pub mod proofs;
#[cfg(target_arch = "wasm32")]
mod worker_pool;

use arithmetic::*;
pub use bigint::U256;
use curve::{Secp256k1, Tom256k1};
use parse::*;
use pedersen::PedersenCycle;
use proofs::*;

use futures_channel::oneshot;
use rand_core::OsRng;
use rayon::prelude::*;
use wasm_bindgen::prelude::*;
pub use wasm_bindgen_rayon::init_thread_pool;

#[cfg(not(target_arch = "wasm32"))]
pub fn build_thread_pool() -> Result<rayon::ThreadPool, String> {
    rayon::ThreadPoolBuilder::new()
        .build()
        .map_err(|e| e.to_string())
}

#[cfg(target_arch = "wasm32")]
fn build_thread_pool(
    pool: &worker_pool::WorkerPool,
    concurrency: usize,
) -> Result<rayon::ThreadPool, String> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(concurrency)
        .spawn_handler(|thread| Ok(pool.run(|| thread.run()).unwrap()))
        .build()
        .map_err(|e| e.to_string())
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn logv(x: &JsValue);
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "generateExpInput")]
pub fn generate_exp_input(input: JsValue) -> Result<JsValue, JsValue> {
    let mut rng = rand_core::OsRng;
    let pedersen = PedersenCycle::<Secp256k1, Tom256k1>::new(&mut rng);

    let input: ParsedProofInput<Secp256k1> = input
        .into_serde::<ProofInput>()
        .map_err(|e| e.to_string())?
        .try_into()?;

    let s_inv = input.signature.s.inverse();
    let r_inv = input.signature.r.inverse();
    let u1 = s_inv * input.msg_hash;
    let u2 = s_inv * input.signature.r;
    let r_point = Point::<Secp256k1>::GENERATOR.double_mul(&u1, &Point::from(&input.pubkey), &u2);
    let s1 = r_inv * input.signature.s;
    let z1 = r_inv * input.msg_hash;
    let q_point = &Point::<Secp256k1>::GENERATOR * z1;

    let commitment_to_s1 = pedersen
        .base()
        .commit_with_generator(&mut rng, s1, &r_point);
    let commitment_to_pk_x = pedersen
        .cycle()
        .commit(&mut rng, input.pubkey.x().to_cycle_scalar());
    let commitment_to_pk_y = pedersen
        .cycle()
        .commit(&mut rng, input.pubkey.y().to_cycle_scalar());

    // TODO membership proof
    let secrets = ExpSecrets::new(s1, input.pubkey);
    let commitments = ExpCommitments {
        px: commitment_to_pk_x,
        py: commitment_to_pk_y,
        exp: commitment_to_s1,
    };

    let exp_proof_input = ExpProofInput {
        pedersen,
        secrets,
        commitments,
        r_point,
        q_point,
    };

    JsValue::from_serde(&exp_proof_input).map_err(|e| JsValue::from(e.to_string()))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "generateExpProof")]
pub fn generate_exp_proof(
    input: JsValue,
    worker_pool: worker_pool::WorkerPool,
    concurrency: u32,
) -> Vec<u8> {
    let input: ExpProofInput<Secp256k1, Tom256k1> =
        input.into_serde().map_err(|e| e.to_string()).unwrap();
    let security_param = 60_usize; // TODO
                                   //let aux_vec: Vec<AuxiliaryCommitments<Secp256k1, Tom256k1>> = (0..security_param)
    (0..security_param)
        .into_par_iter()
        .map(|_| {
            //std::thread::sleep(std::time::Duration::from_secs(1));
            let mut rng = OsRng;
            // exponent
            let mut alpha = Scalar::ZERO;
            while alpha == Scalar::ZERO {
                // ensure alpha is non-zero
                alpha = Scalar::random(&mut rng);
            }
            // random r scalars
            let r = Scalar::random(&mut rng);
            // T = g^alpha
            let t: AffinePoint<Secp256k1> = (&input.r_point * alpha).into();
            // A = g^alpha + h^r (essentially a commitment in the base curve)
            let a = &t + &(input.pedersen.base().generator() * r).to_affine();
            // commitment to Tx
            let tx = input
                .pedersen
                .cycle()
                .commit(&mut rng, t.x().to_cycle_scalar());
            // commitment to Ty
            let ty = input
                .pedersen
                .cycle()
                .commit(&mut rng, t.y().to_cycle_scalar());

            //AuxiliaryCommitments {
            //    alpha,
            //    r,
            //    a,
            //    t,
            //    tx,
            //    ty,
            //}
            12_u8
        })
        .collect()
}
