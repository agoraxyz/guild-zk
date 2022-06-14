#![feature(int_log)]
pub mod arithmetic;
pub mod curve;
mod hasher;
pub mod parse;
pub mod pedersen;
pub mod proofs;
#[cfg(target_arch = "wasm32")]
mod worker_pool;

pub use bigint::U256;
#[cfg(target_arch = "wasm32")]
use curve::{Secp256k1, Tom256k1};
#[cfg(target_arch = "wasm32")]
use parse::*;
#[cfg(target_arch = "wasm32")]
use pedersen::PedersenCycle;
#[cfg(target_arch = "wasm32")]
use proofs::ZkAttestProof;
use wasm_bindgen::prelude::*;

#[cfg(not(target_arch = "wasm32"))]
pub fn build_thread_pool() -> Result<rayon::ThreadPool, String> {
    rayon::ThreadPoolBuilder::new()
        .build()
        .map_err(|e| e.to_string())
}

#[cfg(target_arch = "wasm32")]
fn build_thread_pool(pool: &worker_pool::WorkerPool) -> Result<rayon::ThreadPool, String> {
    rayon::ThreadPoolBuilder::new()
        .build()
        .spawn_handler(|thread| Ok(pool.run(|| thread.run()).unwrap()))
        .map_err(|e| e.to_string())
}

#[cfg(target_arch = "wasm32")]
macro_rules! console_log {
    ($($t:tt)*) => (crate::log(&format_args!($($t)*).to_string()))
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn logv(x: &JsValue);
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "generateProof")]
pub async fn generate_proof(
    input: JsValue,
    ring: JsValue,
    worker_pool: &worker_pool::WorkerPool,
) -> Result<JsValue, JsValue> {
    let mut rng = rand_core::OsRng;
    let pedersen = PedersenCycle::<Secp256k1, Tom256k1>::new(&mut rng);

    let input: ParsedProofInput<Secp256k1> = input
        .into_serde::<ProofInput>()
        .map_err(|e| e.to_string())?
        .try_into()?;

    let ring: ParsedRing<Tom256k1> =
        parse_ring(ring.into_serde::<Ring>().map_err(|e| e.to_string())?)?;

    let thread_pool = build_thread_pool(&worker_pool);

    let zk_attest_proof =
        ZkAttestProof::construct(rng, pedersen, input, &ring, &thread_pool).await?;

    JsValue::from_serde(&zk_attest_proof).map_err(|e| JsValue::from(e.to_string()))
}

// This function is only for wasm test purposes as the
// verification is done on the backend in pure rust.
// TODO: put this behind a wasm-test feature flag?
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "verifyProof")]
pub fn verify_proof(
    proof: JsValue,
    ring: JsValue,
    worker_pool: &worker_pool::WorkerPool,
) -> Result<JsValue, JsValue> {
    let proof: ZkAttestProof<Secp256k1, Tom256k1> =
        proof.into_serde().map_err(|e| e.to_string())?;

    let ring: ParsedRing<Tom256k1> =
        parse_ring(ring.into_serde::<Ring>().map_err(|e| e.to_string())?)?;

    let thread_pool = build_thread_pool(&worker_pool);

    proof.verify(rand_core::OsRng, &ring, &thread_pool)?;
    Ok(JsValue::from(true))
}
