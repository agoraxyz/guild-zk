#![feature(int_log)]

// this macro needs to come before 'mod worker_pool'
#[cfg(target_arch = "wasm32")]
macro_rules! console_log {
    ($($t:tt)*) => (crate::log(&format_args!($($t)*).to_string()))
}

pub mod arithmetic;
pub mod curve;
pub mod hasher;
pub mod parse;
pub mod pedersen;
//pub mod proofs;
//#[cfg(target_arch = "wasm32")]
//mod worker_pool;

pub use bigint::U256;
/*
use arithmetic::*;
#[cfg(target_arch = "wasm32")]
use curve::{Secp256k1, Tom256k1};
#[cfg(target_arch = "wasm32")]
use parse::*;
#[cfg(target_arch = "wasm32")]
use pedersen::PedersenCycle;
#[cfg(target_arch = "wasm32")]
use proofs::*;

use futures_channel::oneshot;
use rayon::prelude::*;
use wasm_bindgen::prelude::*;

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
*/

/*
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "generateProof")]
pub async fn generate_proof(
    input: JsValue,
    ring: JsValue,
    worker_pool: worker_pool::WorkerPool,
) -> Result<JsValue, JsValue> {
    let mut rng = rand_core::OsRng;
    let pedersen = Box::leak(Box::new(PedersenCycle::<Secp256k1, Tom256k1>::new(
        &mut rng,
    )));

    let input: ParsedProofInput<Secp256k1> = input
        .into_serde::<ProofInput>()
        .map_err(|e| e.to_string())?
        .try_into()?;

    let ring: ParsedRing<Tom256k1> =
        parse_ring(ring.into_serde::<Ring>().map_err(|e| e.to_string())?)?;

    let thread_pool = Box::leak(Box::new(build_thread_pool(&worker_pool)?));

    let proof =
        ZkAttestProof::construct(rng, pedersen, input, &ring, thread_pool, worker_pool).await?;
    JsValue::from_serde(&proof).map_err(|e| e.to_string().into())
}
*/

/*
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "generateAux")]
pub fn generate_aux(
    input: JsValue,
    worker_pool: worker_pool::WorkerPool,
    concurrency: u32,
) -> Result<js_sys::Promise, JsValue> {
    let mut rng = rand_core::OsRng;
    let pedersen = PedersenCycle::<Secp256k1, Tom256k1>::new(&mut rng);
    let thread_pool = build_thread_pool(&worker_pool, concurrency as usize)?;
    let input: ParsedProofInput<Secp256k1> = input
        .into_serde::<ProofInput>()
        .map_err(|e| e.to_string())?
        .try_into()?;

    // signature arithmetic
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

    let security_param = 60_usize;
    let mut aux_vec = vec![0; security_param];
    let (tx, rx) = oneshot::channel();
    // auxiliary parameters
    worker_pool.run(move || {
        thread_pool.install(|| {
            //let aux_vec: Vec<AuxiliaryCommitments<C, CC>> = (0..security_param)
                aux_vec.par_iter_mut().for_each(|elem| {
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
                    let t: AffinePoint<Secp256k1> = (&r_point * alpha).into();
                    // A = g^alpha + h^r (essentially a commitment in the base curve)
                    let a = &t + &(pedersen.base().generator() * r).to_affine();

                    // commitment to Tx
                    //let tx = pedersen.cycle().commit(&mut rng, t.x().to_cycle_scalar());
                    // commitment to Ty
                    //let ty = pedersen.cycle().commit(&mut rng, t.y().to_cycle_scalar());

                    //let _aux = AuxiliaryCommitments {
                    //    alpha,
                    //    r,
                    //    a,
                    //    t,
                    //    tx,
                    //    ty,
                    //};
                    *elem = 12_u8
                });
        });
        drop(tx.send(aux_vec))
    })?;

    let done = async move {
        match rx.await {
            Ok(p) => Ok(JsValue::from(js_sys::Uint8Array::from(p.as_slice()))),
            Err(e) => Err(JsValue::from(e.to_string())),
        }
    };

    Ok(wasm_bindgen_futures::future_to_promise(done))
}
*/
